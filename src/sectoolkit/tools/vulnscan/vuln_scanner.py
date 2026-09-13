"""Vuln Scanner — W4 Vuln Scanning.

Banner-grabs services on the specified ports, classifies the service, and
matches each banner against a small curated CVE rule set (bundled data/cves.json,
optionally extended with --cve-rules-file). Reports matched CVEs with severity.
"""

from __future__ import annotations

import json
import re
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

from ...core.datadir import data_file
from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="vuln-scanner",
    title="Vuln Scanner (banner + CVE match)",
    wave=4,
    description=(
        "Connect, banner-grab, and classify services on the given ports; match "
        "banners against a curated CVE database (bundled + optional custom "
        "rules)."
    ),
    category="vulnscan",
    mode="act",
    privileges="none",
    target_fields=["host"],
    fields=[
        FieldSpec(name="host", label="Target host", type="host", required=True),
        FieldSpec(name="ports", label="Ports (comma/range list)", type="text",
                  default="21,22,25,80,443,3306,5432,8080"),
        FieldSpec(name="timeout", label="Connect timeout (s)", type="int", default=3),
        FieldSpec(name="cve_rules_file", label="Extra CVE rules JSON (optional)", type="file",
                  default=None,
                  help="list of {id, service, pattern, cvss, desc, ref}"),
    ],
)

_HTTP_PORTS = {80, 443, 8000, 8080, 8443, 8888, 9000}


def _parse_ports(spec: str) -> List[int]:
    from ...core.netutil import parse_port_spec
    return parse_port_spec(spec)


def _load_rules(extra: Optional[str]) -> List[dict]:
    rules = json.loads(data_file("cves.json").read_text(encoding="utf-8"))
    if extra:
        rules.extend(json.loads(open(extra, encoding="utf-8").read()))
    for i, r in enumerate(rules):
        for key in ("id", "service", "pattern", "cvss", "desc"):
            if key not in r:
                raise ValueError(f"cve rule #{i} missing {key!r}")
        re.compile(r["pattern"])  # validate now
    return rules


def _classify(banner: str, port: int) -> str:
    b = banner.lower()
    if "ssh" in b:
        return "ssh"
    if "http" in b or "apache" in b or "nginx" in b or "iis" in b or "coyote" in b:
        return "http"
    if "ftp" in b or b.startswith("220"):
        return "ftp"
    if "smtp" in b or b.startswith("220 ") and "esmtp" in b:
        return "smtp"
    if "telnet" in b or "urarat" in b:
        return "telnet"
    return {21: "ftp", 25: "smtp", 80: "http", 443: "http",
            3306: "mysql", 5432: "postgres", 23: "telnet"}.get(port, "unknown")


def _match_rules(banner: str, service: str, rules: List[dict]) -> List[dict]:
    hits = []
    for r in rules:
        if service == "http" and r["service"] == "smtp":
            continue
        try:
            if re.search(r["pattern"], banner, re.IGNORECASE):
                if r["service"] == service or r["service"] in ("http", "ftp", "ssh"):
                    hits.append(dict(r))
        except re.error:
            continue
    return hits


def _grab_banner(host: str, port: int, timeout: float) -> Optional[str]:
    b = bytearray()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n" %
                      host.encode()) if port in _HTTP_PORTS else None
            s.sendall(b"\r\n") if port not in _HTTP_PORTS else None
            end = time.monotonic() + timeout
            while time.monotonic() < end and len(b) < 4096:
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    break
                except OSError:
                    break
                if not chunk:
                    break
                b.extend(chunk)
    except OSError:
        return None
    return decode_banner(bytes(b))


def _clean(raw: bytes) -> str:
    text = raw.decode("latin-1", "replace")
    return "".join(ch if (ch.isprintable() or ch in "\t") else " " for ch in text)


def decode_banner(raw: bytes) -> str:
    """Decode and sanitize a raw banner for safe matching/display."""
    return " ".join(_clean(raw).split())[:1024]


def _fingerprint_banner(banner: str) -> Dict[str, str]:
    out = {"product": "", "version": ""}
    m = re.search(r"([A-Za-z][A-Za-z0-9_]*)[_/ ](\d[\w.]*)", banner)
    if m:
        product = m.group(1)
        if not product.lower().startswith(("ssh-", "http", "ftp", "smtp")):
            out["product"] = product
            out["version"] = m.group(2)
    return out


def run(params: dict, ctx: ToolContext) -> dict:
    host = str(params.get("host") or "").strip()
    if not host:
        raise ValueError("host is required")
    try:
        ports = _parse_ports(str(params.get("ports") or "21,22,25,80,443"))
    except ValueError as exc:
        raise ValueError(f"ports: {exc}") from exc
    try:
        timeout = float(params.get("timeout") or 3)
    except (TypeError, ValueError):
        raise ValueError("timeout must be a number")
    if timeout <= 0 or timeout > 60:
        raise ValueError("timeout must be in (0, 60]")
    rules = _load_rules(params.get("cve_rules_file"))

    start = datetime.now(timezone.utc)
    results: List[dict] = []
    lock = threading.Lock()

    def scan(port: int) -> None:
        banner = _grab_banner(host, port, timeout)
        service = "closed"
        matched: List[dict] = []
        if banner is not None:
            service = _classify(banner, port)
            matched = _match_rules(banner, service, rules)
        with lock:
            results.append({
                "port": port,
                "service": service,
                "banner": banner or "",
                "fingerprint": _fingerprint_banner(banner) if banner else {},
                "cves": matched,
            })

    threads = [threading.Thread(target=scan, args=(p,)) for p in ports]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    results.sort(key=lambda r: r["port"])
    scanned = len(results)
    open_ports = [r for r in results if r["banner"]]
    vulnerable = [r for r in results if r["cves"]]
    return {
        "host": host,
        "ports_scanned": scanned,
        "open_ports": len(open_ports),
        "vulnerable_services": len(vulnerable),
        "results": results,
        "scanned_at": start.isoformat(),
    }


def render(result: dict) -> str:
    lines = [f"Vuln scan {result['host']}: "
             f"{result['ports_scanned']} ports, {result['open_ports']} open, "
             f"{result['vulnerable_services']} vulnerable"]
    for r in result.get("results", []):
        if not r["banner"]:
            continue
        lines.append(f"  :{r['port']:<5} {r['service']:<8} {r['banner'][:80]}")
        for c in r.get("cves", []):
            lines.append(f"      * {c['id']} (CVSS {c['cvss']}) {c['desc']}")
    return "\n".join(lines)