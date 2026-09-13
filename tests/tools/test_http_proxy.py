"""Tests for the HTTP proxy (lab gating + real GET and CONNECT flows)."""

from __future__ import annotations

import socket
import threading
import time

import pytest

from sectoolkit.tools.proxy import http_proxy as hp


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


def _http_origin(port, stop):
    """Minimal origin HTTP server replying 200 with a fixed body."""
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
                conn.recv(4096)
                body = b"<html>origin-body</html>"
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nServer: OriginLab\r\n"
                    + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                    + body)
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
        m = hp.TOOL
        assert m.wave == 3 and m.category == "proxy" and m.mode == "act"

    def test_invalid_port(self, sample_context):
        with pytest.raises(ValueError):
            hp.run({"listen_host": "127.0.0.1", "listen_port": 70000}, sample_context)


class TestEndToEnd:
    def test_get_absolute_form(self, sample_context):
        stop = threading.Event()
        sample_context.extra["stop_event"] = stop
        origin_port = _free_port()
        proxy_port = _free_port()
        threading.Thread(target=_http_origin, args=(origin_port, stop),
                         daemon=True).start()

        results: dict = {}
        def run_proxy():
            results["p"] = hp.run({"listen_host": "127.0.0.1",
                                   "listen_port": proxy_port, "duration": 0},
                                  sample_context)
        t = threading.Thread(target=run_proxy, daemon=True)
        t.start()
        _wait_listener(proxy_port)
        try:
            req = (f"GET http://127.0.0.1:{origin_port}/lab HTTP/1.1\r\n"
                   "Host: 127.0.0.1\r\nUser-Agent: proxytest\r\n"
                   "Proxy-Connection: keep-alive\r\nConnection: close\r\n\r\n")
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as s:
                s.sendall(req.encode())
                resp = b""
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    resp += chunk
            assert b"HTTP/1.1 200 OK" in resp
            assert b"origin-body" in resp
        finally:
            stop.set()
            t.join(timeout=5)
        log = results["p"]["requests_log"]
        assert any(r["method"] == "GET" and r["status"] == 200
                   and r["target"] == f"127.0.0.1:{origin_port}"
                   and r["user_agent"] == "proxytest" for r in log)

    def test_connect_tunnel_relay(self, sample_context):
        stop = threading.Event()
        sample_context.extra["stop_event"] = stop
        echo_port = _free_port()
        proxy_port = _free_port()

        # raw TCP echo endpoint (proxy CONNECT tunnels to it)
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
                            conn.sendall(b"T:" + data)
                    except OSError:
                        pass
                    finally:
                        try:
                            conn.close()
                        except OSError:
                            pass

                threading.Thread(target=handle, args=(c,), daemon=True).start()
            srv.close()

        threading.Thread(target=echo_server, daemon=True).start()

        results: dict = {}
        def run_proxy():
            results["p"] = hp.run({"listen_host": "127.0.0.1",
                                   "listen_port": proxy_port, "duration": 0},
                                  sample_context)
        t = threading.Thread(target=run_proxy, daemon=True)
        t.start()
        _wait_listener(proxy_port)
        try:
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as s:
                s.sendall(f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n"
                          "Host: 127.0.0.1\r\n\r\n".encode())
                data = s.recv(1024)
                assert b"200 Connection established" in data
                s.sendall(b"through the tunnel")
                echoed = s.recv(1024)
                assert echoed == b"T:through the tunnel"
        finally:
            stop.set()
            t.join(timeout=5)
        assert any(r["method"] == "CONNECT" and r["status"] == 200
                   for r in results["p"]["requests_log"])

    def test_render_readable(self):
        text = hp.render({
            "listen": "127.0.0.1:8080", "requests": 1,
            "requests_log": [{"client": "127.0.0.1:5", "method": "GET",
                              "target": "127.0.0.1:80", "user_agent": "curl/8",
                              "status": 200}],
        })
        assert "127.0.0.1:8080" in text and "curl/8" in text