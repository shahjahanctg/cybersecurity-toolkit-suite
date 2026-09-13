"""HTTP Proxy — W3 Proxy & Tunnel.

A minimal forward HTTP proxy:
  * plain HTTP requests (absolute-form URL) are relayed to origin hosts;
  * CONNECT requests tunnel raw bytes to the target host (TLS passthrough).

Every request is logged {client, method, url/host, user_agent, status}.
"""

from __future__ import annotations

import re
import socket
import threading
import time
from datetime import datetime, timezone
from typing import List
from urllib.parse import urlparse

from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="http-proxy",
    title="HTTP Proxy (GET + CONNECT)",
    wave=3,
    description=(
        "Minimal forward HTTP proxy: relaying absolute-form HTTP requests and "
        "CONNECT tunnels. Logs client, target, user-agent, and status per "
        "request."
    ),
    category="proxy",
    mode="act",
    privileges="none",
    target_fields=["listen_host"],
    fields=[
        FieldSpec(name="listen_host", label="Listen address", type="host",
                  default="127.0.0.1",
                  help="Interface to bind (0.0.0.0 for all interfaces)"),
        FieldSpec(name="listen_port", label="Listen port", type="int",
                  default=8080, help="0 = pick a free port"),
        FieldSpec(name="duration", label="Run duration (s, 0=until stop)", type="int",
                  default=60, help="0 runs until Cancelled (Ctrl-C / GUI stop)"),
        FieldSpec(name="max_connections", label="Max connections", type="int",
                  default=100),
    ],
)

_HOP_BY_HOP = {
    "proxy-connection", "proxy-authorization", "connection", "keep-alive",
    "proxy-authenticate", "te", "trailer", "transfer-encoding", "upgrade",
}

_SANITIZE_REQ = re.compile(r"[^\x09\x0a\x0d\x20-\x7e\x80-\xff]")


def _sanitize(text: str) -> str:
    return _SANITIZE_REQ.sub("", text or "")


def _err(client: socket.socket, code: int, reason: str) -> None:
    body = f"<html><body><h1>{code} {reason}</h1></body></html>".encode()
    try:
        client.sendall(
            f"HTTP/1.1 {code} {reason}\r\nContent-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body)
    except OSError:
        pass


def _connect_to(host: str, port: int, timeout: float = 8.0) -> socket.socket:
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(30.0)
    return s


def _relay_pair(a: socket.socket, b: socket.socket) -> None:
    def pump(src, dst):
        while True:
            try:
                data = src.recv(65536)
            except OSError:
                return
            if not data:
                return
            try:
                dst.sendall(data)
            except OSError:
                return
    t1 = threading.Thread(target=pump, args=(a, b), daemon=True)
    t2 = threading.Thread(target=pump, args=(b, a), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()


def _handle_http(client: socket.socket, addr: tuple, log: list) -> None:
    request = bytearray()
    try:
        client.settimeout(5.0)
        while b"\r\n\r\n" not in bytes(request):
            chunk = client.recv(65536)
            if not chunk:
                return
            request.extend(chunk)
            if len(request) > 1 << 20:
                return
    except OSError:
        return
    client.settimeout(30.0)

    text = bytes(request).decode("utf-8", "replace")
    lines = _sanitize(text).split("\r\n")
    head = lines[0]
    toks = head.split()
    if not toks:
        return
    first, version = toks[0].upper(), (toks[2] if len(toks) > 2 else "HTTP/1.1")
    if first == "CONNECT":
        if len(toks) < 2:
            return
        authority = toks[1]
        host, sep, port_s = authority.rpartition(":")
        if not sep:
            log.append({"client": f"{addr[0]}:{addr[1]}", "method": "CONNECT",
                        "target": authority, "user_agent": "", "status": 400})
            return
        if not host:
            log.append({"client": f"{addr[0]}:{addr[1]}", "method": "CONNECT",
                        "target": authority, "user_agent": "", "status": 400})
            _err(client, 400, "Bad Request")
            return
        try:
            port = int(port_s)
        except ValueError:
            log.append({"client": f"{addr[0]}:{addr[1]}", "method": "CONNECT",
                        "target": authority, "user_agent": "", "status": 400})
            return
        try:
            upstream = _connect_to(host, port)
        except OSError:
            log.append({"client": f"{addr[0]}:{addr[1]}", "method": "CONNECT",
                        "target": f"{host}:{port}", "user_agent": "",
                        "status": 502})
            _err(client, 502, "Bad Gateway (upstream unreachable)")
            return
        log.append({"client": f"{addr[0]}:{addr[1]}", "method": "CONNECT",
                    "target": f"{host}:{port}", "user_agent": "",
                    "status": 200})
        try:
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            _relay_pair(client, upstream)
        finally:
            try:
                upstream.close()
            except OSError:
                pass
        return

    # plain HTTP: parse absolute-form or origin-form with Host header
    ua = ""
    host = ""
    for line in lines[1:]:
        k, _, v = line.partition(":")
        k = k.strip().lower()
        v = v.strip()
        if k == "user-agent":
            ua = v
        elif k == "host" and not host:
            host = v

    parts = toks[1:] if len(toks) > 1 else []
    url = parts[0] if parts else ""
    if url.startswith("http://"):
        parsed = urlparse(url)
        host, port = (parsed.hostname or ""), (parsed.port or 80)
        path = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
    else:
        path = url or "/"
        host = host
        port = 80

    if not host:
        log.append({"client": f"{addr[0]}:{addr[1]}", "method": first,
                    "target": "(no host)", "user_agent": ua, "status": 400})
        return

    try:
        upstream = _connect_to(host, port)
    except (OSError, socket.timeout):
        log.append({"client": f"{addr[0]}:{addr[1]}", "method": first,
                    "target": f"{host}:{port}", "user_agent": ua, "status": 502})
        _err(client, 502, "Bad Gateway (upstream unreachable)")
        return

    headers_out = []
    for line in lines[1:]:
        k = line.partition(":")[0].strip().lower()
        if k not in _HOP_BY_HOP:
            headers_out.append(line)
    headers_out.append("Connection: close")
    new_req = [f"{first} {path} {version}"]
    new_req.extend(headers_out)
    payload = ("\r\n".join(new_req) + "\r\n\r\n").encode("utf-8")

    try:
        upstream.sendall(payload)
        response = bytearray()
        while b"\r\n\r\n" not in bytes(response):
            chunk = upstream.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
            if len(response) > 1 << 20:
                break
        status = 502
        headline = bytes(response).decode("utf-8", "replace").split("\r\n")[0] if response else ""
        m = re.match(r"HTTP/\d\.\d\s+(\d{3})", headline)
        if m:
            status = int(m.group(1))
        if response:
            client.sendall(bytes(response))
        # stream the rest of the body
        while True:
            chunk = upstream.recv(65536)
            if not chunk:
                break
            client.sendall(chunk)
        log.append({"client": f"{addr[0]}:{addr[1]}", "method": first,
                    "target": f"{host}:{port}", "user_agent": ua, "status": status})
    except OSError:
        pass
    finally:
        try:
            upstream.close()
        except OSError:
            pass


def run(params: dict, ctx: ToolContext) -> dict:
    listen_host = str(params.get("listen_host") or "127.0.0.1").strip()
    try:
        listen_port = int(params.get("listen_port") or 8080)
    except (TypeError, ValueError):
        raise ValueError("listen_port must be an integer")
    if not 0 <= listen_port <= 65535:
        raise ValueError("listen_port must be between 0 and 65535")
    duration = int(params.get("duration") or 60)
    if duration < 0:
        raise ValueError("duration must be >= 0")
    max_connections = int(params.get("max_connections") or 100)
    if max_connections < 1:
        raise ValueError("max_connections must be >= 1")

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((listen_host, listen_port))
    except OSError as exc:
        raise ValueError(f"cannot bind {listen_host}:{listen_port}: {exc}") from exc
    listener.listen(max_connections)
    listener.settimeout(0.5)
    actual_port = listener.getsockname()[1]

    deadline = None if duration == 0 else time.monotonic() + duration
    stop_event = ctx.extra.get("stop_event")
    start = datetime.now(timezone.utc)
    log: List[dict] = []
    log_lock = threading.Lock()
    ctx.logger.info("http-proxy listening on %s:%s", listen_host, actual_port)

    try:
        while True:
            if stop_event is not None and stop_event.is_set():
                break
            if deadline is not None and time.monotonic() >= deadline:
                break
            try:
                conn, addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            def handle(client=conn, a=addr):
                try:
                    _handle_http(client, a, log)
                    with log_lock:
                        if len(log) > 500:
                            del log[: len(log) - 500]
                finally:
                    try:
                        client.close()
                    except OSError:
                        pass

            threading.Thread(target=handle, daemon=True).start()
    finally:
        listener.close()

    return {
        "listen": f"{listen_host}:{actual_port}",
        "requests": len(log),
        "requests_log": log,
        "started_at": start.isoformat(),
        "ended_at": datetime.now(timezone.utc).isoformat(),
    }


def render(result: dict) -> str:
    lines = [f"HTTP proxy {result.get('listen', '?')}  ->  "
             f"{result.get('requests', 0)} request(s)"]
    for r in result.get("requests_log", []):
        lines.append(f"  {r['client']:<22} {r.get('method','?'):<7} "
                     f"{r['target']:<40} {r.get('user_agent','')[:24]:<24} "
                     f"{r.get('status','?')}")
    return "\n".join(lines)