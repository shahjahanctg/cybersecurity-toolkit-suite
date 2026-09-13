"""Tests for the port scanner: happy path against local sockets, errors, privilege gate."""

from __future__ import annotations

import socket
import threading

import pytest

from sectoolkit.tools.network import port_scanner
from sectoolkit.core.netutil import parse_port_spec


@pytest.fixture
def tcp_server():
    """One open TCP port (echoes a banner) on 127.0.0.1; returns its port."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    port = server.getsockname()[1]
    stop = threading.Event()

    def serve():
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
            finally:
                conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield port
    stop.set()
    server.close()


class TestPortSpec:
    def test_specs(self):
        assert parse_port_spec("80") == [80]
        assert parse_port_spec("80,443,1-4") == [1, 2, 3, 4, 80, 443]


class TestTcpConnect:
    def test_open_port_detected(self, tcp_server, sample_context):
        result = port_scanner.run(
            {"host": "127.0.0.1", "ports": str(tcp_server),
             "scan_type": "tcp_connect", "timeout": 2, "threads": 50},
            sample_context)
        assert result["open_count"] == 1
        assert result["results"][0]["port"] == tcp_server
        assert result["results"][0]["state"] == "open"

    def test_version_banner(self, tcp_server, sample_context):
        result = port_scanner.run(
            {"host": "127.0.0.1", "ports": str(tcp_server),
             "scan_type": "version", "timeout": 2, "threads": 10},
            sample_context)
        assert "OpenSSH" in result["results"][0]["banner"]

    def test_closed_port_ignored_in_render(self, sample_context):
        result = port_scanner.run(
            {"host": "127.0.0.1", "ports": "65000-65002",
             "scan_type": "tcp_connect", "timeout": 1, "threads": 10},
            sample_context)
        assert result["open_count"] == 0
        text = port_scanner.render(result)
        assert "closed" not in text


class TestErrors:
    @pytest.mark.parametrize("bad_ports", ["abc", "0", "70000"])
    def test_invalid_port_spec(self, bad_ports, sample_context):
        with pytest.raises(ValueError):
            port_scanner.run(
                {"host": "127.0.0.1", "ports": bad_ports,
                 "scan_type": "tcp_connect", "timeout": 2},
                sample_context)

    def test_bad_timeout_bounds(self, sample_context):
        with pytest.raises(ValueError):
            port_scanner.run(
                {"host": "127.0.0.1", "ports": "80", "scan_type": "tcp_connect",
                 "timeout": 99},
                sample_context)

    def test_invalid_host(self, sample_context):
        with pytest.raises(ValueError):
            port_scanner.run(
                {"host": "$(rm -rf /)", "ports": "80",
                 "scan_type": "tcp_connect", "timeout": 2},
                sample_context)


class TestSynPrivilege:
    def test_syn_without_caps_fails_fast(self, sample_context, monkeypatch):
        monkeypatch.setattr(port_scanner, "do_have_raw_sockets", lambda: (False, "no caps"))
        with pytest.raises(PermissionError):
            port_scanner.run(
                {"host": "127.0.0.1", "ports": "80", "scan_type": "syn",
                 "timeout": 2},
                sample_context)