"""SOCKS5 proxy — W3 Proxy & Tunnel.

A minimal forward SOCKS5 proxy implementing the RFC 1928 no-auth subset:
- greeting (no methods -> 0xFF, no-auth -> 0x00)
- CONNECT (0x01): byte-level TCP tunnel
- UDP ASSOCIATE (0x03): SOCKS5-framed UDP relay on a local bind port
- BIND (0x02): unsupported (REP 0x07)
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import struct
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from ...core.tool import FieldSpec, ToolContext, ToolMeta

log = logging.getLogger("sectoolkit.socks5")

TOOL = ToolMeta(
    name="socks5-proxy",
    title="SOCKS5 Proxy (no-auth, CONNECT + UDP ASSOCIATE)",
    wave=3,
    description=(
        "RFC 1928 SOCKS5 forward proxy: no-auth, CONNECT tunnels and UDP "
        "ASSOCIATE relay. Events logged per connection."
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
                  default=1080),
        FieldSpec(name="duration", label="Run duration (s, 0=until stop)", type="int",
                  default=60, help="0 runs until Cancelled (Ctrl-C / GUI stop)"),
    ],
)

_VERSION = 0x05
_CMD_CONNECT = 0x01
_CMD_BIND = 0x02
_CMD_UDP = 0x03
_ATYP_IPV4 = 0x01
_ATYP_DOMAIN = 0x03
_ATYP_IPV6 = 0x04

_REP_SUCCEEDED = 0x00
_REP_NET_UNREACH = 0x03
_REP_CMD_UNSUPPORTED = 0x07


def _recvn(conn: socket.socket, n: int, timeout: float = 8.0) -> bytes:
    conn.settimeout(timeout)
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise EOFError("peer closed during handshake")
        buf.extend(chunk)
    return bytes(buf)


def _read_addressed(conn: socket.socket, atyp: int) -> Tuple[str, int]:
    if atyp == _ATYP_IPV4:
        raw = _recvn(conn, 4)
        host = str(ipaddress.IPv4Address(raw))
    elif atyp == _ATYP_DOMAIN:
        ln = _recvn(conn, 1)[0]
        if ln == 0:
            raise ValueError("empty domain")
        host = _recvn(conn, ln).decode("latin-1")
    elif atyp == _ATYP_IPV6:
        raw = _recvn(conn, 16)
        host = str(ipaddress.IPv6Address(raw))
    else:
        raise ValueError(f"unknown ATYP {atyp}")
    port = struct.unpack("!H", _recvn(conn, 2))[0]
    return host, port


def _pump(a: socket.socket, b: socket.socket, stats: dict) -> None:
    while True:
        try:
            data = a.recv(65536)
        except OSError:
            return
        if not data:
            return
        try:
            b.sendall(data)
        except OSError:
            return
        stats["bytes"] += len(data)


def _handle_connect(conn: socket.socket, host: str, port: int,
                    log_entries: list, addr, stop_event) -> None:
    upstream = socket.create_connection((host, port), timeout=8)
    upstream.settimeout(None)
    conn.sendall(bytes([_VERSION, _REP_SUCCEEDED, 0x00, _ATYP_IPV4]) +
                 b"\x00\x00\x00\x00\x00\x00")
    log_entries.append({"client": f"{addr[0]}:{addr[1]}", "command": "CONNECT",
                        "target": f"{host}:{port}", "status": 200})
    stats = {"bytes": 0}
    t1 = threading.Thread(target=_pump, args=(conn, upstream, stats), daemon=True)
    t2 = threading.Thread(target=_pump, args=(upstream, conn, stats), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()
    for s in (conn, upstream):
        try:
            s.close()
        except OSError:
            pass
    log_entries[-1]["status"] = 200
    log_entries[-1]["bytes"] = stats["bytes"]


def _handle_udp(conn: socket.socket, addr, log_entries: list, stop_event) -> None:
    relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    relay.bind(("127.0.0.1", 0))
    relay.settimeout(0.5)
    bnd_port = relay.getsockname()[1]
    conn.sendall(bytes([_VERSION, _REP_SUCCEEDED, 0x00, _ATYP_IPV4]) +
                 socket.inet_aton("127.0.0.1") + struct.pack("!H", bnd_port))
    log_entries.append({"client": f"{addr[0]}:{addr[1]}", "command": "UDP",
                        "target": f"127.0.0.1:{bnd_port}", "status": 200})

    clients: Dict[Tuple, tuple] = {}
    dropped = {"count": 0}
    udp_log: list = []

    def datagram_target(data: bytes) -> Optional[Tuple[str, int, bytes]]:
        """Parse a SOCKS5 UDP request, return (host, port, payload)."""
        if len(data) < 4 or data[0] != 0x00 or data[1] != 0x00:
            return None
        frag = data[2]
        if frag != 0:
            return None
        atyp = data[3]
        try:
            if atyp == _ATYP_IPV4:
                host = str(ipaddress.IPv4Address(data[4:8]))
                port = struct.unpack("!H", data[8:10])[0]
                return host, port, data[10:]
            if atyp == _ATYP_DOMAIN:
                ln = data[4]
                host = data[5:5 + ln].decode("latin-1")
                base = 5 + ln
                port = struct.unpack("!H", data[base:base + 2])[0]
                return host, port, data[base + 2:]
            if atyp == _ATYP_IPV6:
                host = str(ipaddress.IPv6Address(data[4:20]))
                port = struct.unpack("!H", data[20:22])[0]
                return host, port, data[22:]
        except (ValueError, IndexError, struct.error):
            return None
        return None

    def wrap(host: str, port: int, payload: bytes) -> bytes:
        try:
            ip = ipaddress.ip_address(host)
            if ip.version == 4:
                return b"\x00\x00\x00\x01" + ip.packed + struct.pack("!H", port) + payload
            return b"\x00\x00\x00\x04" + ip.packed + struct.pack("!H", port) + payload
        except ValueError:
            hostb = host.encode("latin-1")
            return b"\x00\x00\x03" + bytes([len(hostb)]) + hostb + struct.pack("!H", port) + payload

    stop = threading.Event()

    def _find_client(src):
        for ckey, (chost, cport) in clients.items():
            if src[0] == chost and src[1] == cport:
                return ckey
        return None

    def relay_loop() -> None:
        while not stop.is_set():
            try:
                data, src = relay.recvfrom(65536)
            except socket.timeout:
                continue
            except OSError:
                return
            parsed = datagram_target(data)
            if parsed is not None:
                dhost, dport, payload = parsed
                clients[src] = (dhost, dport)
                try:
                    relay.sendto(payload, (dhost, dport))
                except OSError:
                    continue
            else:
                # Not a SOCKS frame: treat as a reply from the destination.
                key = _find_client(src)
                if key is None:
                    dropped["count"] += 1
                    continue
                try:
                    relay.sendto(wrap(src[0], src[1], data), key)
                except OSError:
                    continue

    t1 = threading.Thread(target=relay_loop, daemon=True)
    t1.start()
    conn.settimeout(0.5)
    while True:
        if stop_event is not None and stop_event.is_set():
            break
        try:
            if conn.recv(1) == b"":
                break
        except socket.timeout:
            continue
        except OSError:
            break
    stop.set()
    t1.join(timeout=2)
    relay.close()
    for k, v in clients.items():
        udp_log.append({"client": f"{k[0]}:{k[1]}", "target": f"{v[0]}:{v[1]}"})
    log_entries[-1]["peers"] = len(udp_log)


def _handle_client(conn: socket.socket, addr, log_entries: list, log_lock,
                   stop_event) -> None:
    try:
        header = _recvn(conn, 2, timeout=8)
        if len(header) < 2 or header[0] != _VERSION:
            return
        nmethods = header[1]
        methods = _recvn(conn, nmethods, timeout=8) if nmethods else b""
        if 0x00 in methods:
            conn.sendall(bytes([_VERSION, 0x00]))
        else:
            conn.sendall(bytes([_VERSION, 0xFF]))
            return
        req = _recvn(conn, 4, timeout=8)
        if len(req) < 4 or req[0] != _VERSION:
            return
        cmd, atyp = req[1], req[3]
        host, port = _read_addressed(conn, atyp)
        if not (0 <= port <= 65535):
            conn.close()
            return
        if cmd not in (_CMD_CONNECT, _CMD_UDP):
            with log_lock:
                log_entries.append({"client": f"{addr[0]}:{addr[1]}",
                                    "command": "BIND" if cmd == _CMD_BIND else f"CMD{cmd}",
                                    "target": f"{host}:{port}", "status": 501})
            conn.sendall(bytes([_VERSION, _REP_CMD_UNSUPPORTED, 0x00, _ATYP_IPV4]) +
                         b"\x00\x00\x00\x00\x00\x00")
            return
        if cmd == _CMD_CONNECT:
            try:
                _handle_connect(conn, host, port, log_entries, addr, stop_event)
            except (OSError, socket.timeout, ValueError):
                with log_lock:
                    log_entries.append({"client": f"{addr[0]}:{addr[1]}",
                                        "command": "CONNECT",
                                        "target": f"{host}:{port}", "status": 503})
                conn.sendall(bytes([_VERSION, _REP_NET_UNREACH, 0x00, _ATYP_IPV4]) +
                             b"\x00\x00\x00\x00\x00\x00")
        else:
            _handle_udp(conn, addr, log_entries, stop_event)
    except (OSError, EOFError, ValueError):
        try:
            conn.close()
        except OSError:
            pass


def run(params: dict, ctx: ToolContext) -> dict:
    listen_host = str(params.get("listen_host") or "127.0.0.1").strip()
    try:
        listen_port = int(params.get("listen_port") or 1080)
    except (TypeError, ValueError):
        raise ValueError("listen_port must be an integer")
    if not (0 <= listen_port <= 65535):
        raise ValueError("listen_port must be between 0 and 65535")
    duration = int(params.get("duration") or 60)
    if duration < 0:
        raise ValueError("duration must be >= 0")

    stop_event = ctx.extra.get("stop_event")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((listen_host, listen_port))
    except OSError as exc:
        raise ValueError(f"cannot bind {listen_host}:{listen_port}: {exc}") from exc
    listener.listen(128)
    listener.settimeout(0.5)
    actual_port = listener.getsockname()[1]

    log_entries: list = []
    log_lock = threading.Lock()
    threads: list = []
    deadline = None if duration == 0 else time.monotonic() + duration
    start = datetime.now(timezone.utc)

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
            th = threading.Thread(target=_handle_client,
                                  args=(conn, addr, log_entries, log_lock, stop_event),
                                  daemon=True)
            th.start()
            threads.append(th)
    finally:
        listener.close()

    live = sum(1 for th in threads if th.is_alive())
    return {
        "listen": f"{listen_host}:{actual_port}",
        "connections": len(threads),
        "active_connections": live,
        "requests_log": log_entries[-200:],
        "started_at": start.isoformat(),
    }


def render(result: dict) -> str:
    lines = [
        "SOCKS5 proxy",
        f"  listen      : {result.get('listen', '')}",
        f"  connections : {result.get('connections', 0)} total, "
        f"{result.get('active_connections', 0)} active",
    ]
    for r in result.get("requests_log", []):
        lines.append(
            f"  * {r.get('client', '')}  {r.get('command', '')}  "
            f"{r.get('target', '')}  ->  {r.get('status', '?')}"
            + (f"  ({r.get('bytes', 0)} B)" if "bytes" in r else ""))
    return "\n".join(lines)