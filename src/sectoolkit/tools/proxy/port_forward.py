"""Port Forwarder — W3 Proxy & Tunnel.

A bidirectional TCP/UDP relay. In `forward` mode the tool listens on your side
and streams traffic to a target service (the classic proxy). In `reverse`
mode the same relay listens where the exposed service appears to live and
forwards to your collector (orientation label; the mechanism is identical).
"""

from __future__ import annotations

import socket
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List

from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="port-forward",
    title="Port Forwarder (TCP/UDP relay)",
    wave=3,
    description=(
        "Bidirectional TCP/UDP port relay in forward or reverse orientation. "
        "Streams traffic between a listen socket and a target host:port."
    ),
    category="proxy",
    mode="act",
    privileges="none",
    target_fields=["listen_host", "target_host"],
    fields=[
        FieldSpec(name="mode", label="Orientation", type="combo",
                  options=["forward", "reverse"], default="forward",
                  help="forward: listen -> target; reverse: same relay from "
                       "the exposed side to your collector"),
        FieldSpec(name="proto", label="Protocol", type="combo",
                  options=["tcp", "udp"], default="tcp"),
        FieldSpec(name="listen_host", label="Listen address", type="host",
                  default="127.0.0.1",
                  help="Interface to bind (0.0.0.0 for all interfaces)"),
        FieldSpec(name="listen_port", label="Listen port", type="int",
                  default=9090, help="0 = pick a free port"),
        FieldSpec(name="target_host", label="Target host", type="host",
                  default="127.0.0.1"),
        FieldSpec(name="target_port", label="Target port", type="int",
                  default=80),
        FieldSpec(name="duration", label="Run duration (s, 0=until stop)", type="int",
                  default=60, help="0 runs until Cancelled (Ctrl-C / GUI stop)"),
        FieldSpec(name="max_connections", label="Max TCP connections", type="int",
                  default=100, help="UDP sessions are tracked implicitly"),
    ],
)


class _Stats:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.conns = 0
        self.to_target = 0
        self.to_client = 0

    def record(self, to_target: int = 0, to_client: int = 0, conns: int = 0) -> None:
        with self.lock:
            self.conns += conns
            self.to_target += to_target
            self.to_client += to_client


def _tcp_relay(mode: str, listen_host: str, listen_port: int,
               target_host: str, target_port: int, duration: int,
               max_connections: int, stop_event) -> dict:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((listen_host, listen_port))
    except OSError as exc:
        raise ValueError(f"cannot bind {listen_host}:{listen_port}: {exc}") from exc
    listener.listen(max_connections)
    listener.settimeout(0.5)
    actual_port = listener.getsockname()[1]

    stats = _Stats()
    sessions: List[dict] = []
    sessions_lock = threading.Lock()
    deadline = None if duration == 0 else time.monotonic() + duration
    start = datetime.now(timezone.utc)

    def pump(a, b, direction: str) -> None:
        while True:
            try:
                data = a.recv(65536)
            except OSError:
                return
            if not data or stop_event is not None and stop_event.is_set():
                return
            try:
                b.sendall(data)
            except OSError:
                return
            stats.record(to_target=len(data) if direction == "t" else 0,
                         to_client=len(data) if direction == "c" else 0)

    def handle(conn, addr) -> None:
        try:
            upstream = socket.create_connection((target_host, target_port), timeout=5)
        except OSError as exc:
            try:
                conn.close()
            except OSError:
                pass
            return
        stats.record(conns=1)
        with sessions_lock:
            sessions.append({"client": f"{addr[0]}:{addr[1]}",
                             "target": f"{target_host}:{target_port}"})
            if len(sessions) > 100:
                del sessions[:-100]  # bounded
        try:
            t1 = threading.Thread(target=pump, args=(conn, upstream, "t"), daemon=True)
            t2 = threading.Thread(target=pump, args=(upstream, conn, "c"), daemon=True)
            t1.start(); t2.start()
            t1.join(); t2.join()
        finally:
            for s in (conn, upstream):
                try:
                    s.close()
                except OSError:
                    pass

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
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
    finally:
        listener.close()

    return {
        "protocol": "tcp",
        "orientation": mode,
        "listen": f"{listen_host}:{actual_port}",
        "target": f"{target_host}:{target_port}",
        "connections": len(sessions),
        "bytes_to_target": stats.to_target,
        "bytes_to_client": stats.to_client,
        "sessions": sessions,
        "started_at": start.isoformat(),
    }


def _udp_relay(mode: str, listen_host: str, listen_port: int,
               target_host: str, target_port: int, duration: int,
               stop_event) -> dict:
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        listener.bind((listen_host, listen_port))
    except OSError as exc:
        raise ValueError(f"cannot bind {listen_host}:{listen_port}: {exc}") from exc
    listener.settimeout(0.5)
    actual_port = listener.getsockname()[1]
    target = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target.settimeout(0.5)

    stats = _Stats()
    deadline = None if duration == 0 else time.monotonic() + duration
    start = datetime.now(timezone.utc)
    clients: Dict[str, tuple] = {}  # client addr -> last seen
    clients_lock = threading.Lock()

    def to_target_loop() -> None:
        while True:
            if stop_event is not None and stop_event.is_set():
                return
            if deadline is not None and time.monotonic() >= deadline:
                return
            try:
                data, addr = listener.recvfrom(65536)
            except socket.timeout:
                continue
            except OSError:
                return
            if not data:
                continue
            target.sendto(data, (target_host, target_port))
            with clients_lock:
                clients[addr] = time.monotonic()
            stats.record(to_target=len(data))

    def to_client_loop() -> None:
        while True:
            if stop_event is not None and stop_event.is_set():
                return
            if deadline is not None and time.monotonic() >= deadline:
                return
            try:
                data, addr = target.recvfrom(65536)
            except socket.timeout:
                continue
            except OSError:
                return
            if not data:
                continue
            with clients_lock:
                if not clients:
                    continue
                client = min(clients, key=clients.get)  # most recent-ish mapping
            try:
                listener.sendto(data, client)
                stats.record(to_client=len(data))
            except OSError:
                continue

    t1 = threading.Thread(target=to_target_loop, daemon=True)
    t2 = threading.Thread(target=to_client_loop, daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()

    with clients_lock:
        session_count = len(clients)
    for s in (listener, target):
        try:
            s.close()
        except OSError:
            pass
    return {
        "protocol": "udp",
        "orientation": mode,
        "listen": f"{listen_host}:{actual_port}",
        "target": f"{target_host}:{target_port}",
        "connections": session_count,
        "bytes_to_target": stats.to_target,
        "bytes_to_client": stats.to_client,
        "started_at": start.isoformat(),
    }


def run(params: dict, ctx: ToolContext) -> dict:
    mode = params.get("mode", "forward")
    proto = params.get("proto", "tcp")
    if mode not in ("forward", "reverse"):
        raise ValueError("mode must be forward or reverse")
    if proto not in ("tcp", "udp"):
        raise ValueError("proto must be tcp or udp")
    listen_host = str(params.get("listen_host") or "127.0.0.1").strip()
    target_host = str(params.get("target_host") or "127.0.0.1").strip()
    try:
        listen_port = int(params.get("listen_port") or 0)
        target_port = int(params.get("target_port") or 0)
    except (TypeError, ValueError):
        raise ValueError("ports must be integers")
    if not (0 <= listen_port <= 65535 and 0 <= target_port <= 65535):
        raise ValueError("ports must be between 0 and 65535")
    duration = int(params.get("duration") or 60)
    if duration < 0:
        raise ValueError("duration must be >= 0")

    stop_event = ctx.extra.get("stop_event")
    if proto == "udp":
        return _udp_relay(mode, listen_host, listen_port, target_host,
                          target_port, duration, stop_event)
    max_connections = int(params.get("max_connections") or 100)
    if max_connections < 1:
        raise ValueError("max_connections must be >= 1")
    return _tcp_relay(mode, listen_host, listen_port, target_host, target_port,
                      duration, max_connections, stop_event)


def render(result: dict) -> str:
    approx = "~" if result.get("connections") and result.get("protocol") == "udp" else ""
    lines = [
        f"{result['orientation'].title()} relay {result['protocol'].upper()}",
        f"  listen : {result['listen']}",
        f"  target : {result['target']}",
        f"  sessions: {approx}{result.get('connections', 0)}",
        f"  bytes to target : {result.get('bytes_to_target', 0)}",
        f"  bytes to client : {result.get('bytes_to_client', 0)}",
    ]
    for s in result.get("sessions", []):
        lines.append(f"  * {s['client']} -> {s['target']}")
    return "\n".join(lines)