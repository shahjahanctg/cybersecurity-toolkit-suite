"""Tests for the port forwarder (lab gating + real TCP/UDP relay)."""

from __future__ import annotations

import socket
import threading
import time

import pytest

from sectoolkit.tools.proxy import port_forward as pf


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
    raise TimeoutError("relay did not start")


def _echo_tcp(port, stop):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
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
                    conn.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

        threading.Thread(target=handle, args=(c,), daemon=True).start()
    srv.close()


class TestGating:
    def test_meta(self):
        m = pf.TOOL
        assert m.wave == 3 and m.category == "proxy" and m.mode == "act"
        assert "listen_host" in m.target_fields and "target_host" in m.target_fields

    def test_invalid_proto(self, sample_context):
        with pytest.raises(ValueError):
            pf.run({"mode": "forward", "proto": "sctp", "listen_port": 0}, sample_context)


class TestTcpRelay:
    def test_forward_tcp_echo(self, sample_context):
        stop = threading.Event()
        sample_context.extra["stop_event"] = stop
        target_port = _free_port()
        listener_port = _free_port()
        threading.Thread(target=_echo_tcp, args=(target_port, stop),
                         daemon=True).start()

        thread = threading.Thread(target=lambda: pf.run(
            {"mode": "forward", "proto": "tcp", "listen_host": "127.0.0.1",
             "listen_port": listener_port, "target_host": "127.0.0.1",
             "target_port": target_port, "duration": 0}, sample_context), daemon=True)
        thread.start()
        _wait_listener(listener_port)

        with socket.create_connection(("127.0.0.1", listener_port), timeout=2) as s:
            s.sendall(b"ping via forwarder")
            resp = s.recv(1024)
            assert resp == b"ping via forwarder"
        stop.set()
        thread.join(timeout=5)
        assert not thread.is_alive()

    def test_reverse_is_same_relay(self, sample_context):
        stop = threading.Event()
        sample_context.extra["stop_event"] = stop
        target_port = _free_port()
        listener_port = _free_port()
        threading.Thread(target=_echo_tcp, args=(target_port, stop),
                         daemon=True).start()
        results: dict = {}

        def run_rev():
            results["r"] = pf.run(
                {"mode": "reverse", "proto": "tcp", "listen_host": "127.0.0.1",
                 "listen_port": listener_port, "target_host": "127.0.0.1",
                 "target_port": target_port, "duration": 0}, sample_context)

        thread = threading.Thread(target=run_rev, daemon=True)
        thread.start()
        _wait_listener(listener_port)
        with socket.create_connection(("127.0.0.1", listener_port), timeout=2) as s:
            s.sendall(b"reverse-echo")
            assert s.recv(1024) == b"reverse-echo"
        stop.set()
        thread.join(timeout=5)
        assert results["r"]["orientation"] == "reverse"
        assert results["r"]["sessions"]  # at least one session recorded


class TestUdpRelay:
    def test_udp_echo(self, sample_context):
        stop = threading.Event()
        sample_context.extra["stop_event"] = stop
        target_port = _free_port()

        # UDP echo endpoint
        echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        echo.bind(("127.0.0.1", target_port))
        echo.settimeout(0.2)
        echoed = []

        def echo_loop():
            while not stop.is_set():
                try:
                    data, addr = echo.recvfrom(65536)
                except socket.timeout:
                    continue
                except OSError:
                    return
                echoed.append(data)
                echo.sendto(data.upper(), addr)

        threading.Thread(target=echo_loop, daemon=True).start()

        listener_port = _free_port()
        thread = threading.Thread(target=lambda: pf.run(
            {"mode": "forward", "proto": "udp", "listen_host": "127.0.0.1",
             "listen_port": listener_port, "target_host": "127.0.0.1",
             "target_port": target_port, "duration": 0}, sample_context), daemon=True)
        thread.start()

        # wait until the relay accepts datagrams
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(3.0)
        got = None
        for _ in range(20):
            client.sendto(b"udp-probe", ("127.0.0.1", listener_port))
            try:
                data, _ = client.recvfrom(65536)
                got = data
                break
            except socket.timeout:
                time.sleep(0.1)
        stop.set()
        time.sleep(0.3)
        echo.close()
        client.close()
        thread.join(timeout=5)
        assert got == b"UDP-PROBE"


class TestRender:
    def test_render_readable(self):
        text = pf.render({
            "orientation": "forward", "protocol": "tcp", "listen": "127.0.0.1:9090",
            "target": "127.0.0.1:80", "connections": 2,
            "bytes_to_target": 10, "bytes_to_client": 20,
            "sessions": [{"client": "127.0.0.1:1", "target": "127.0.0.1:80"}],
        })
        assert "127.0.0.1:9090" in text and "sessions" in text.lower()