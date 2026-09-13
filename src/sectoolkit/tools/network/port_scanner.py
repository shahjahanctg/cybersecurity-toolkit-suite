"""Port Scanner — W1 Network Recon.

Three scan modes:
  * tcp_connect  — full TCP handshake (no privileges, slower, reliable)
  * syn          — half-open SYN scan via raw sockets (CAP_NET_RAW/root)
  * version      — TCP connect + banner grab + service-name mapping

Authorized use only: point this at hosts you own or are permitted to assess.
"""

from __future__ import annotations

import concurrent.futures
import socket
import threading
import time
from typing import List, Optional

from ...core.netutil import parse_port_spec, resolve_literal_host
from ...core.privileges import do_have_raw_sockets
from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="port-scan",
    title="Port Scanner (TCP / SYN / version)",
    wave=1,
    description=(
        "Scan a host for open ports using TCP connect, a half-open SYN scan, "
        "or banner-based service/version detection."
    ),
    category="network",
    mode="act",
    privileges="none",
    fields=[
        FieldSpec(name="host", label="Target host", type="text", required=True,
                  placeholder="scanme.example.org  or  10.0.0.5",
                  help="Hostname or IP address of a target you are authorized to scan"),
        FieldSpec(name="ports", label="Ports", type="text", default="1-1024",
                  placeholder="80,443   or  1-1024   or  22,80,443,3306",
                  help="Port list or range, comma-separated"),
        FieldSpec(name="scan_type", label="Scan type", type="combo",
                  default="tcp_connect",
                  options=["tcp_connect", "syn", "version"],
                  help="tcp_connect: full handshake (no privileges); "
                       "syn: half-open (needs raw sockets); version: banner grab"),
        FieldSpec(name="timeout", label="Timeout (s)", type="int", default=3,
                  help="Per-connection timeout in seconds"),
        FieldSpec(name="threads", label="Max threads", type="int", default=200,
                  help="Concurrent probes (bounded by config max_threads)"),
        FieldSpec(name="resolve_hosts", label="Resolve hostname", type="bool", default=False,
                  help="Reverse-resolve the target hostname"),
    ],
)

_MAX_BANNER = 2048
_SCAN_TIMEOUT_LIMIT = 30

# Common service names for well-known ports (best-effort).
_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    514: "syslog", 587: "submission", 636: "ldaps", 873: "rsync",
    990: "ftps", 993: "imaps", 995: "pop3s", 1080: "socks",
    1433: "mssql", 1521: "oracle", 1723: "pptp", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 5985: "winrm-http",
    5986: "winrm-https", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb",
}


def _stop_requested(should_stop) -> bool:
    try:
        return bool(should_stop and should_stop.is_set())
    except AttributeError:
        return False


def _grab_banner(host: str, port: int, timeout: int) -> str:
    """Try to read a short banner after connecting (best-effort)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(_MAX_BANNER)
            except OSError:
                data = b""
            if not data:
                return ""
            text = data.decode("utf-8", errors="replace").strip()
            return " ".join(text.split())[:_MAX_BANNER]
    except OSError:
        return ""


def _tcp_probe(host: str, port: int, timeout: int) -> tuple:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return ("open", "")
    except (ConnectionRefusedError, socket.timeout, OSError):
        return ("closed", "")
    finally:
        s.close()


def _syn_probe(host: str, port: int, timeout: int) -> tuple:
    """Half-open SYN probe using Scapy. Requires raw sockets."""
    from scapy.all import IP, TCP, sr1
    ans = sr1(
        IP(dst=host) / TCP(dport=port, flags="S"),
        timeout=max(1, timeout),
        verbose=False,
    )
    if ans is None:
        return ("filtered", "")
    if ans.haslayer(TCP):
        flags = int(ans.getlayer(TCP).flags)
        if flags & 0x12 == 0x12:  # SA — SYN/ACK, port open
            return ("open", "")
        if flags & 0x14 == 0x14:  # RA — RST/ACK, port closed
            return ("closed", "")
    return ("filtered", "")


def scan_ports(
    host: str,
    ports: List[int],
    scan_type: str = "tcp_connect",
    timeout: int = 3,
    max_workers: int = 200,
    should_stop=None,
) -> List[dict]:
    results: List[dict] = []
    lock = threading.Lock()
    total = len(ports)

    def probe(port: int):
        if _stop_requested(should_stop):
            return None
        if scan_type == "syn":
            state, reason = _syn_probe(host, port, timeout)
            banner = ""
        else:
            state, reason = _tcp_probe(host, port, timeout)
            banner = ""
            if state == "open" and scan_type == "version":
                banner = _grab_banner(host, port, min(timeout, 5))
        with lock:
            results.append({
                "port": port,
                "state": state,
                "service": _SERVICES.get(port, ""),
                "banner": banner,
                "reason": reason,
            })

    workers = min(max(1, max_workers), 512)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(probe, p) for p in ports]
        for f in futures:
            try:
                f.result()
            except Exception:
                pass

    results.sort(key=lambda r: r["port"])
    return results


def run(params: dict, ctx: ToolContext) -> dict:
    host = resolve_literal_host(str(params.get("host", "")))
    ports = parse_port_spec(str(params.get("ports") or "1-1024"))
    scan_type = params.get("scan_type", "tcp_connect")
    timeout = int(params.get("timeout") or 3)
    max_workers = int(params.get("threads") or 200)
    resolve_hosts = bool(params.get("resolve_hosts", False))
    should_stop = ctx.extra.get("stop_event")

    if timeout < 1 or timeout > _SCAN_TIMEOUT_LIMIT:
        raise ValueError(f"timeout must be between 1 and {_SCAN_TIMEOUT_LIMIT}s")
    if len(ports) > 65535:
        raise ValueError("port list too large")

    if scan_type == "syn":
        ok, detail = do_have_raw_sockets()
        if not ok:
            raise PermissionError(
                f"SYN scan needs raw socket capability. Detected: {detail}. "
                "On Linux run as root or grant CAP_NET_RAW.")

    name = ""
    if resolve_hosts:
        try:
            name = socket.gethostbyaddr(host)[0]
        except (socket.herror, socket.gaierror, OSError):
            name = ""

    start = time.time()
    results = scan_ports(host, ports, scan_type, timeout, max_workers, should_stop)
    duration_ms = int((time.time() - start) * 1000)

    open_ports = [r for r in results if r["state"] in ("open", "open-filtered")]

    out = {
        "host": host,
        "hostname": name,
        "scan_type": scan_type,
        "scanned_ports": len(ports),
        "open_count": len(open_ports),
        "duration_ms": duration_ms,
        "results": [
            {k: v for k, v in r.items() if not (scan_type != "version" and k == "banner" and not r[k])}
            for r in results
        ],
    }
    return out


def render(result: dict) -> str:
    lines = [
        f"{result['scan_type']} scan of {result['host']} "
        f"({result.get('hostname') or 'no reverse name'})",
        f"ports scanned: {result['scanned_ports']}   open: {result['open_count']}"
        f"   duration: {result['duration_ms']} ms",
        "",
        f"{'PORT':<8}{'STATE':<12}{'SERVICE':<16}{'BANNER'}",
        "-" * 80,
    ]
    for r in result["results"]:
        if r["state"] == "closed":
            continue
        banner = (r.get("banner") or "").replace("\n", " ").strip()
        lines.append(
            f"{r['port']:<8}{r['state']:<12}{r.get('service', ''):<16}{banner}")
    return "\n".join(lines)