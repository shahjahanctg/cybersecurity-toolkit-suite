"""Honeypot — W2 Defense & Monitoring.

An interactive trap listener that emulates a weak SSH or HTTP service and
captures connection fingerprints (client banner / User-Agent, handshake
bytes, recorded credential probes) into a transcript and an optional JSON
report.

It is a deception tool — using it against systems/networks you do not
control is illegal in most jurisdictions.
"""

from __future__ import annotations

import base64
import json
import socket
import threading
import time
from datetime import datetime, timezone
from typing import List, Optional

from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="honeypot",
    title="Honeypot (SSH/HTTP trap)",
    wave=2,
    description=(
        "Interactive trap listener emulating a weak SSH or HTTP service. "
        "Captures client fingerprints (SSH version banner / User-Agent), "
        "handshake bytes, and recorded credential probes into transcripts."
    ),
    category="defense",
    mode="act",
    privileges="none",
    target_fields=["host"],
    fields=[
        FieldSpec(name="proto", label="Service", type="combo",
                  options=["ssh", "http"], default="ssh"),
        FieldSpec(name="host", label="Bind address", type="host",
                  default="127.0.0.1",
                  help="Interface to bind (0.0.0.0 for all interfaces)"),
        FieldSpec(name="port", label="Port (0=ephemeral)", type="int",
                  default=8022, help="0 picks a free port; typical: 22/8022 ssh, 80/8080 http"),
        FieldSpec(name="banner", label="Server banner", type="text", default="",
                  placeholder="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6 / HTTP auto",
                  help="Empty = built-in default for the chosen service"),
        FieldSpec(name="duration", label="Run duration (s, 0=until stop)", type="int",
                  default=60, help="0 runs until Cancelled (Ctrl-C / GUI stop)"),
        FieldSpec(name="max_connections", label="Max connections", type="int",
                  default=50),
        FieldSpec(name="save_report", label="Save JSON report", type="bool",
                  default=True, help="Write connections report to the output dir"),
    ],
)

SSH_DEFAULT_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
HTTP_DEFAULT_SERVER = "Apache/2.4.52 (Ubuntu)"

_AUTH_ALNUM = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@:/ ")


def _ascii_runs(data: bytes) -> List[str]:
    """Collect printable ASCII runs (heuristic credential/command probes)."""
    runs, cur = [], []
    for byte in data:
        ch = chr(byte)
        if ch in _AUTH_ALNUM:
            cur.append(ch)
        elif cur:
            if len(cur) >= 2:
                runs.append("".join(cur))
            cur = []
    if len(cur) >= 2:
        runs.append("".join(cur))
    return runs


def _guess_ssh_client(banner: str) -> str:
    low = banner.lower()
    if "libssh" in low:
        return "libssh-based (e.g. paramiko)"
    if "openssh" in low:
        return "OpenSSH client"
    if "putty" in low:
        return "PuTTY"
    if "dropbear" in low:
        return "DropBear"
    if "nmap" in low:
        return "nmap script"
    if low.startswith("ssh-"):
        return "SSH client (generic)"
    return "unknown"


def _guess_http_client(ua: str, path: str) -> str:
    low = (ua + " " + path).lower()
    if "sqlmap" in low:
        return "sqlmap"
    if "nmap script" in low or "nmap-scripts" in low:
        return "nmap http-script"
    if "curl/" in low:
        return "curl"
    if "python-requests" in low or "aiohttp" in low or "httpx" in low:
        return "Python HTTP client"
    if "go-http-client" in low:
        return "Go HTTP client"
    if "nikto" in low:
        return "nikto"
    if "wpscan" in low:
        return "wpscan"
    return "browser/unknown"


def _handle_ssh(conn: socket.socket, addr: tuple, banner: str, buffer: bytes) -> dict:
    client_banner = ""
    payload = bytearray(buffer)
    try:
        # the client's first line carries its identification string (banner)
        conn.settimeout(2.0)
        line = b""
        while not line.endswith(b"\n"):
            chunk = conn.recv(512)
            if not chunk:
                break
            line += chunk
            if len(line) > 2048:
                break
        if line:
            payload.extend(line)
            text = line.decode("utf-8", errors="replace").strip()
            if text.lower().startswith("ssh-"):
                client_banner = text
        # drain a short idle window to catch queued credential/auth probes
        conn.settimeout(0.3)
        while len(payload) < 4096:
            try:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                payload.extend(chunk)
            except socket.timeout:
                break
            except OSError:
                break
    except OSError:
        pass

    runs = _ascii_runs(bytes(payload))[-8:]
    probes = [r for r in runs
              if any(k in r.lower() for k in
                     ("user", "pass", "password", "root", "admin", "key", "auth"))]
    return {
        "type": "ssh",
        "client_banner": client_banner,
        "fingerprint": _guess_ssh_client(client_banner),
        "probes": probes,
        "handshake_hex": bytes(payload)[:64].hex(),
    }


def _handle_http(conn: socket.socket, addr: tuple, banner: str, buffer: bytes) -> dict:
    request = bytearray(buffer)
    try:
        conn.settimeout(2.0)
        while b"\r\n\r\n" not in bytes(request):
            chunk = conn.recv(4096)
            if not chunk:
                break
            request.extend(chunk)
            if len(request) > 65536:
                break
    except OSError:
        pass

    text = bytes(request).decode("utf-8", errors="replace")
    lines = text.split("\r\n")
    head = lines[0] if lines else ""
    method, _, rest = head.partition(" ")
    path, _, version = rest.rpartition(" ")
    headers: dict = {}
    auth_scheme, auth_user = "", ""
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers.setdefault(k.strip().lower(), v.strip())
    auth = headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        auth_scheme = "Basic"
        try:
            raw = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8", "replace")
            auth_user, _, _ = raw.partition(":")
        except Exception:
            raw = ""
        auth_user = auth_user if isinstance(auth_user, str) else ""
    elif auth:
        auth_scheme = "bearer/token"

    ua = headers.get("user-agent", "")
    server = banner or HTTP_DEFAULT_SERVER
    body = "<html><body><h1>Not Found</h1></body></html>"
    resp = (f"HTTP/1.1 404 Not Found\r\nServer: {server}\r\n"
            f"Content-Type: text/html\r\nContent-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n" + body)
    try:
        conn.sendall(resp.encode("utf-8"))
    except OSError:
        pass

    return {
        "type": "http",
        "request_line": head,
        "method": method or "",
        "path": path or "",
        "http_version": version or "",
        "user_agent": ua,
        "auth_scheme": auth_scheme,
        "auth_user": auth_user,
        "header_count": len(headers),
        "fingerprint": _guess_http_client(ua, path or ""),
        "handshake_hex": bytes(request)[:64].hex(),
    }


def run(params: dict, ctx: ToolContext) -> dict:
    proto = params.get("proto", "ssh")
    host = str(params.get("host") or "127.0.0.1").strip()
    try:
        port = int(params.get("port") or 8022)
    except (TypeError, ValueError):
        raise ValueError("port must be an integer")
    if not 0 <= port <= 65535:
        raise ValueError("port must be between 0 and 65535")
    banner = str(params.get("banner") or "").strip()
    duration = int(params.get("duration") or 60)
    if duration < 0:
        raise ValueError("duration must be >= 0")
    try:
        max_connections = int(params.get("max_connections") or 50)
    except (TypeError, ValueError):
        raise ValueError("max_connections must be an integer")
    if max_connections < 1:
        raise ValueError("max_connections must be >= 1")

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((host, port))
    except OSError as exc:
        raise ValueError(f"cannot bind {host}:{port}: {exc}") from exc
    listener.listen(max_connections)
    actual_port = listener.getsockname()[1]
    listener.settimeout(0.5)

    started = datetime.now(timezone.utc)
    deadline = None if duration == 0 else time.monotonic() + duration
    stop_event = ctx.extra.get("stop_event")
    connections: List[dict] = []
    conn_id = 0
    logging = ctx.logger

    logging.info("honeypot %s listening on %s:%s (duration=%s)",
                 proto, host, actual_port, duration)
    try:
        while True:
            if stop_event is not None and stop_event.is_set():
                logging.info("honeypot cancelled by stop event")
                break
            if deadline is not None and time.monotonic() >= deadline:
                break
            try:
                conn, addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn_id += 1
            logging.info("connection #%s from %s:%s", conn_id, addr[0], addr[1])

            def handle(c: socket.socket, a: tuple, cid: int) -> None:
                buffer = b""
                try:
                    c.settimeout(0.5)
                    if proto == "ssh":
                        server_banner = banner or SSH_DEFAULT_BANNER
                        try:
                            c.sendall((server_banner + "\r\n").encode("utf-8"))
                        except OSError:
                            pass
                        info = _handle_ssh(c, a, server_banner, buffer)
                        info.update(cid=cid, client=a[0], client_port=a[1],
                                    bytes_received=0)
                    else:
                        info = _handle_http(c, a, banner, buffer)
                        info.update(cid=cid, client=a[0], client_port=a[1],
                                    bytes_received=len(buffer))
                    connections.append(info)
                finally:
                    try:
                        c.close()
                    except OSError:
                        pass

            t = threading.Thread(target=handle, args=(conn, addr, conn_id),
                                 daemon=True)
            t.start()
    finally:
        listener.close()

    ended = datetime.now(timezone.utc)
    report_path = None
    if params.get("save_report", True):
        report = {
            "tool": "honeypot",
            "proto": proto,
            "bind_address": f"{host}:{actual_port}",
            "started_at": started.isoformat(),
            "ended_at": ended.isoformat(),
            "connections_count": len(connections),
            "connections": connections,
        }
        ctx.ensure_output_dir()
        filename = f"honeypot-{proto}-{int(started.timestamp())}.json"
        report_path = ctx.output_dir / filename
        report_path.write_text(json.dumps(report, indent=1), encoding="utf-8")

    return {
        "proto": proto,
        "bind_address": f"{host}:{actual_port}",
        "started_at": started.isoformat(),
        "ended_at": ended.isoformat(),
        "connections_count": len(connections),
        "connections": connections,
        "report_path": str(report_path) if report_path else None,
    }


def render(result: dict) -> str:
    lines = [
        f"Honeypot ({result['proto']}) ran {result.get('bind_address', '?')}  ->  "
        f"{result.get('connections_count', 0)} connection(s)",
    ]
    for conn in result.get("connections", []):
        lines.append("")
        lines.append(f"  #{conn['cid']} {conn['client']}:{conn['client_port']}  "
                     f"fingerprint: {conn['fingerprint']}")
        if conn["type"] == "ssh":
            lines.append(f"    banner   : {conn['client_banner'] or '(none)'}")
            for probe in conn.get("probes", []):
                lines.append(f"    probe    : {probe!r}")
        else:
            lines.append(f"    {conn.get('method')} {conn.get('path')}  "
                         f"{conn['user_agent'] or '(no UA)'}"
                         + (f"  auth={conn['auth_scheme']} {conn.get('auth_user')!r}"
                            if conn.get("auth_user") else ""))
    if result.get("report_path"):
        lines.append("")
        lines.append(f"report: {result['report_path']}")
    return "\n".join(lines)