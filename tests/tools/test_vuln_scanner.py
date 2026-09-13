"""Tests for the vuln scanner (gating + banner/CVE matching against live sockets)."""

from __future__ import annotations

import json
import socket
import threading
import time

import pytest

from sectoolkit.tools.vulnscan import vuln_scanner as vs


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _FakeService:
    """TCP listener that sends a fixed banner then keeps the conn open."""

    def __init__(self, banner: bytes):
        self.banner = banner
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.port = self.srv.getsockname()[1]
        self.srv.listen(5)
        self.srv.settimeout(0.3)
        self.stop = threading.Event()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self.stop.is_set():
            try:
                c, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                c.sendall(self.banner)
            except OSError:
                pass
            threading.Thread(target=self._keep, args=(c,), daemon=True).start()
        self.srv.close()

    def _keep(self, c):
        while not self.stop.is_set():
            try:
                if not c.recv(1024):
                    return
            except OSError:
                return

    def close(self):
        self.stop.set()


class TestGating:
    def test_meta(self):
        m = vs.TOOL
        assert m.wave == 4 and m.category == "vulnscan" and m.mode == "act"

    def test_invalid_ports(self, sample_context):
        with pytest.raises(ValueError):
            vs.run({"host": "127.0.0.1", "ports": "80,foo"}, sample_context)

    def test_missing_host(self, sample_context):
        with pytest.raises(ValueError, match="host"):
            vs.run({"host": "", "ports": "80"}, sample_context)


class TestScan:
    def test_sniffs_openssh_cve(self, sample_context):
        svc = _FakeService(b"SSH-2.0-OpenSSH_7.4p1 Debian\r\n")
        try:
            res = vs.run({"host": "127.0.0.1", "ports": str(svc.port),
                          "timeout": 2}, sample_context)
        finally:
            svc.close()
        r = next(x for x in res["results"] if x["port"] == svc.port)
        assert r["service"] == "ssh"
        assert r["fingerprint"]["product"].lower() == "openssh"
        assert any(c["id"] == "CVE-2018-15473" for c in r["cves"])

    def test_apache_41773(self, sample_context):
        svc = _FakeService(b"HTTP/1.1 400 Bad Request\r\nServer: Apache/2.4.49 (Unix)\r\n\r\n")
        try:
            res = vs.run({"host": "127.0.0.1", "ports": str(svc.port),
                          "timeout": 2}, sample_context)
        finally:
            svc.close()
        r = next(x for x in res["results"] if x["port"] == svc.port)
        assert r["service"] == "http"
        assert any(c["id"] in ("CVE-2021-41773", "CVE-2021-42013") for c in r["cves"])

    def test_closed_port(self, sample_context):
        port = _free_port()
        res = vs.run({"host": "127.0.0.1", "ports": str(port), "timeout": 1},
                     sample_context)
        r = next(x for x in res["results"] if x["port"] == port)
        assert r["service"] == "closed" and not r["cves"]

    def test_custom_rules_file(self, sample_context, tmp_path):
        svc = _FakeService(b"Maestro-Server/4.2 demo\r\n")
        rules = tmp_path / "custom.json"
        rules.write_text(json.dumps([{
            "id": "CVE-XYZ-0001", "service": "ftp", "pattern": "Maestro-Server/4",
            "cvss": "5.0", "desc": "demo rule"}]), encoding="utf-8")
        try:
            res = vs.run({"host": "127.0.0.1", "ports": str(svc.port),
                          "timeout": 2, "cve_rules_file": str(rules)},
                         sample_context)
        finally:
            svc.close()
        r = next(x for x in res["results"] if x["port"] == svc.port)
        assert any(c["id"] == "CVE-XYZ-0001" for c in r["cves"])