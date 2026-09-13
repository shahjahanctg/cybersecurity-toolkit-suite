"""Tests for the honeypot (lab gating, real socket end-to-end, fingerprint heuristics)."""

from __future__ import annotations

import socket
import threading
import time

import pytest

from sectoolkit.tools.defense import honeypot as hp


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_for_listener(host: str, port: int, tries: int = 40):
    for _ in range(tries):
        try:
            with socket.create_connection((host, port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("honeypot did not start listening")


class TestGating:
    def test_meta(self):
        m = hp.TOOL
        assert m.wave == 2 and m.category == "defense" and m.mode == "act"
        assert "host" in m.target_fields

    def test_binds_any_host(self, sample_context):
        result = hp.run({"proto": "ssh", "host": "0.0.0.0", "port": 0,
                         "duration": 1}, sample_context)
        assert result["proto"] == "ssh"
        assert result["connections_count"] == 0

    def test_invalid_port(self, sample_context):
        with pytest.raises(ValueError):
            hp.run({"proto": "ssh", "host": "127.0.0.1", "port": 99999}, sample_context)


class TestHeuristics:
    def test_ascii_runs(self):
        runs = hp._ascii_runs(b"SSH\x00foo\x01root pass_w0rd\nbar")
        joined = " ".join(runs)
        assert "SSH" in runs and "foo" in runs
        assert "root" in joined and "pass_w0rd" in joined

    def test_guess_ssh(self):
        assert "libssh" in hp._guess_ssh_client("SSH-2.0-libssh_0.9.6")
        assert "OpenSSH" in hp._guess_ssh_client("SSH-2.0-OpenSSH_8.9p1")
        assert hp._guess_ssh_client("") == "unknown"

    def test_guess_http(self):
        assert hp._guess_http_client("curl/8.0.1", "/") == "curl"
        assert hp._guess_http_client("python-requests/2.31", "/") == "Python HTTP client"
        assert hp._guess_http_client("sqlmap/1.7", "/?id=1") == "sqlmap"


def _run_ssh_stop(ctx, port, stop, results, extra=""):
    params = {"proto": "ssh", "host": "127.0.0.1", "port": port,
              "duration": 60, "max_connections": 10, "save_report": False}
    params.update(extra)
    results["ssh"] = hp.run(params, ctx)


class TestEndToEnd:
    def test_ssh_fingerprint_and_probes(self, sample_context):
        port = _free_port()
        stop = threading.Event()
        results: dict = {}
        sample_context.extra["stop_event"] = stop
        t = threading.Thread(target=_run_ssh_stop,
                             args=(sample_context, port, stop, results), daemon=True)
        t.start()
        _wait_for_listener("127.0.0.1", port)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as conn:
                banner = conn.recv(256).decode("utf-8", "replace")
                assert banner.startswith("SSH-2.0-OpenSSH")
                conn.sendall(b"SSH-2.0-libssh_0.9.6\r\n")
                conn.sendall(b"\x00password\x00root\x00")
        finally:
            stop.set()
            t.join(timeout=10)
        result = results["ssh"]
        assert result["connections_count"] >= 1
        # connections[0] is the wait-for-listener probe; use the real client
        first = result["connections"][-1]
        assert first["client_banner"].startswith("SSH-2.0-libssh")
        assert "libssh" in first["fingerprint"]
        probes = " ".join(first["probes"])
        assert "root" in probes and "password" in probes

    def test_http_fingerprint_and_basic_auth(self, sample_context):
        port = _free_port()
        stop = threading.Event()
        results: dict = {}
        sample_context.extra["stop_event"] = stop
        params = {"proto": "http", "host": "127.0.0.1", "port": port,
                  "duration": 60, "max_connections": 10}
        t = threading.Thread(target=lambda: results.setdefault(
            "http", hp.run(params, sample_context)), daemon=True)
        t.start()
        _wait_for_listener("127.0.0.1", port)
        try:
            import base64
            auth = base64.b64encode(b"admin:letmein").decode()
            req = (b"GET /admin.php HTTP/1.1\r\nHost: localhost\r\n"
                   b"User-Agent: sqlmap/1.7\r\nAuthorization: Basic "
                   + auth.encode()
                   + b"\r\nConnection: close\r\n\r\n")
            with socket.create_connection(("127.0.0.1", port), timeout=2) as conn:
                conn.sendall(req)
                resp = conn.recv(1024).decode("utf-8", "replace")
                assert "404 Not Found" in resp and "Apache" in resp
        finally:
            stop.set()
            t.join(timeout=10)
        result = results["http"]
        # connections[0] is the wait-for-listener probe (empty request)
        first = result["connections"][-1]
        assert first["method"] == "GET" and first["path"] == "/admin.php"
        assert first["auth_scheme"] == "Basic" and first["auth_user"] == "admin"
        assert first["fingerprint"] == "sqlmap"

    def test_report_written(self, sample_context):
        sample_context.extra["stop_event"] = threading.Event()
        sample_context.extra["stop_event"].set()  # exits immediately
        result = hp.run({"proto": "ssh", "host": "127.0.0.1", "port": 0,
                         "duration": 0, "save_report": True}, sample_context)
        assert result["report_path"]
        from pathlib import Path
        assert Path(result["report_path"]).exists()

    def test_render_readable(self):
        text = hp.render({
            "proto": "ssh", "bind_address": "127.0.0.1:8022",
            "connections_count": 1, "report_path": "/tmp/r.json",
            "connections": [{"cid": 1, "client": "127.0.0.1", "client_port": 50123,
                             "type": "ssh", "client_banner": "SSH-2.0-libssh_0.9.6",
                             "fingerprint": "libssh", "probes": ["root"]}],
        })
        assert "libssh" in text and "50123" in text and "root" in text