"""Tests for the SOCKS5 proxy (gating, CONNECT and UDP ASSOCIATE flows)."""

from __future__ import annotations

import socket
import struct
import threading
import time

import pytest

from sectoolkit.tools.proxy import socks5_proxy as sp


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _wait_listener(port: int, tries: int = 40):
    for _ in range(tries):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("proxy did not start")


def _socks_greet(conn: socket.socket) -> bytes:
    conn.sendall(b"\x05\x01\x00")
    return _recvn(conn, 2)


def _recvn(conn, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return bytes(buf)
        buf.extend(chunk)
    return bytes(buf)


def _send_connect(conn, host: bytes, port: int) -> None:
    req = b"\x05\x01\x00" + b"\x03" + bytes([len(host)]) + host + struct.pack("!H", port)
    conn.sendall(req)


class TestGating:
    def test_meta(self):
        m = sp.TOOL
        assert m.wave == 3 and m.category == "proxy" and m.mode == "act"

    def test_binds_any_host(self, sample_context):
        result = sp.run({"listen_host": "127.0.0.1", "listen_port": 0,
                         "duration": 1}, sample_context)
        listen = result["listen"]
        assert listen.startswith("127.0.0.1:") and int(listen.rsplit(":", 1)[1]) > 0

    def test_invalid_port(self, sample_context):
        with pytest.raises(ValueError):
            sp.run({"listen_host": "127.0.0.1", "listen_port": -5}, sample_context)

    def test_no_auth_method_rejected(self):
        """Offer only username/password auth -> proxy replies 0xFF."""
        stop = threading.Event()
        ctx = None
        port = _free_port()
        results: dict = {}

        from sectoolkit.core.registry import ToolRegistry
        from sectoolkit.core.config import AppConfig
        from sectoolkit.core.logging_setup import get_logger
        from sectoolkit.core.tool import ToolContext
        from pathlib import Path
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        cfg = AppConfig(root=tmp)
        ctx = ToolContext(config=cfg, logger=get_logger("t"), output_dir=tmp / "o",
                          interactive=False)
        ctx.extra["stop_event"] = stop

        def run_proxy():
            results["p"] = sp.run({"listen_host": "127.0.0.1",
                                   "listen_port": port, "duration": 0}, ctx)
        t = threading.Thread(target=run_proxy, daemon=True)
        t.start()
        _wait_listener(port)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
                s.sendall(b"\x05\x01\x02")
                assert _recvn(s, 2) == b"\x05\xff"
        finally:
            stop.set(); t.join(timeout=5)


class TestEndToEnd:
    def test_connect_tunnel(self, sample_context):
        stop = threading.Event()
        sample_context.extra["stop_event"] = stop
        echo_port = _free_port()
        proxy_port = _free_port()

        def echo_server():
            srv = socket.socket()
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", echo_port))
            srv.listen(5)
            srv.settimeout(0.3)
            while not stop.is_set():
                try:
                    c, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                def handle(conn):
                    try:
                        while True:
                            data = conn.recv(4096)
                            if not data:
                                break
                            conn.sendall(b"S:" + data)
                    except OSError:
                        pass
                    finally:
                        conn.close()
                threading.Thread(target=handle, args=(c,), daemon=True).start()
            srv.close()

        threading.Thread(target=echo_server, daemon=True).start()
        results: dict = {}

        def run_proxy():
            results["p"] = sp.run({"listen_host": "127.0.0.1",
                                   "listen_port": proxy_port, "duration": 0},
                                  sample_context)
        t = threading.Thread(target=run_proxy, daemon=True)
        t.start()
        _wait_listener(proxy_port)
        try:
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as s:
                assert _socks_greet(s) == b"\x05\x00"
                _send_connect(s, b"127.0.0.1", echo_port)
                reply = _recvn(s, 10)
                assert reply[0] == 0x05 and reply[1] == 0x00
                s.sendall(b"ping")
                assert _recvn(s, 6) == b"S:ping"
        finally:
            stop.set(); t.join(timeout=5)
        assert any(r["command"] == "CONNECT" and r["status"] == 200
                   and r["target"] == f"127.0.0.1:{echo_port}"
                   for r in results["p"]["requests_log"])

    def test_connect_targets_any_host(self, monkeypatch):
        called: dict = {}

        def fake_connect(addr, timeout):
            called["addr"] = addr
            raise OSError("refused")

        monkeypatch.setattr(sp.socket, "create_connection", fake_connect)
        conn = socket.socket()
        log: list = []
        with pytest.raises(OSError):
            sp._handle_connect(conn, "192.0.2.1", 443, log, ("1.2.3.4", 5),
                               threading.Event())
        assert called["addr"] == ("192.0.2.1", 443)

    def test_udp_associate_relay(self, sample_context):
        stop = threading.Event()
        sample_context.extra["stop_event"] = stop
        udp_target_port = _free_port()
        proxy_port = _free_port()

        # UDP echo target
        echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        echo.bind(("127.0.0.1", udp_target_port))
        echo.settimeout(0.3)

        def echo_loop():
            while not stop.is_set():
                try:
                    data, src = echo.recvfrom(65536)
                except socket.timeout:
                    continue
                except OSError:
                    return
                echo.sendto(b"U:" + data, src)
        threading.Thread(target=echo_loop, daemon=True).start()

        results: dict = {}
        def run_proxy():
            results["p"] = sp.run({"listen_host": "127.0.0.1",
                                   "listen_port": proxy_port, "duration": 0},
                                  sample_context)
        t = threading.Thread(target=run_proxy, daemon=True)
        t.start()
        _wait_listener(proxy_port)

        try:
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as ctcp:
                assert _socks_greet(ctcp) == b"\x05\x00"
                ctcp.sendall(b"\x05\x03\x00" + b"\x01\x00\x00\x00\x00\x00\x00")
                reply = _recvn(ctcp, 10)
                assert reply[0] == 0x05 and reply[1] == 0x00
                bnd_ip = socket.inet_ntoa(reply[4:8])
                bnd_port = struct.unpack("!H", reply[8:10])[0]
                assert bnd_ip == "127.0.0.1"

                # send a framed datagram through the relay
                reporter = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                reporter.settimeout(3.0)
                framed = (b"\x00\x00\x00" + b"\x01" +
                          socket.inet_aton("127.0.0.1") +
                          struct.pack("!H", udp_target_port) + b"hello via socks")
                reporter.sendto(framed, ("127.0.0.1", bnd_port))
                reply_data, _ = reporter.recvfrom(65536)
                assert reply_data.startswith(b"\x00\x00\x00\x01")
                assert reply_data.endswith(b"U:hello via socks")
                reporter.close()

            ctcp.close() if False else None
        finally:
            stop.set()
            t.join(timeout=5)
            echo.close()

    def test_render_readable(self):
        text = sp.render({"listen": "127.0.0.1:1080", "connections": 2,
                          "active_connections": 1,
                          "requests_log": [{"client": "127.0.0.1:5",
                                            "command": "CONNECT",
                                            "target": "127.0.0.1:80",
                                            "status": 200}]})
        assert "127.0.0.1:1080" in text and "CONNECT" in text