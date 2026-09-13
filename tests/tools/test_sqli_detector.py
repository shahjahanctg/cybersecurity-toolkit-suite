"""Tests for the SQLi detector (gating + error-based detection live)."""

from __future__ import annotations

import socket
import threading
import time
from urllib.parse import parse_qs, urlparse

import pytest

from sectoolkit.tools.vulnscan import sqli_detector as sq


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _App:
    """Fake app: echoes 'ERROR SQL syntax' when id contains a quote."""

    def __init__(self):
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.port = self.srv.getsockname()[1]
        self.srv.listen(16)
        self.srv.settimeout(0.2)
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
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()
        self.srv.close()

    def _handle(self, c):
        try:
            data = c.recv(8192)
            if not data:
                return
            path = data.split(b" ")[1].decode("latin-1", "replace")
            qs = urlparse(path).query
            vals = parse_qs(qs)
            inj = "".join(vals.get("id", []))
            if "'" in inj or '"' in inj or "--" in inj:
                body = b"SQL syntax error near '" + inj.encode() + b"'"
            else:
                body = b"OK item"
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " +
                      str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        except (OSError, IndexError):
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    def close(self):
        self.stop.set()


class TestGating:
    def test_meta(self):
        m = sq.TOOL
        assert m.wave == 4 and m.category == "vulnscan" and m.mode == "act"

    def test_bad_scheme(self, sample_context):
        with pytest.raises(ValueError, match="http"):
            sq.run({"target_url": "gopher://127.0.0.1/a"}, sample_context)


class TestDetection:
    def test_error_based_finding(self, sample_context):
        app = _App()
        try:
            res = sq.run({"target_url": f"http://127.0.0.1:{app.port}/item?id={{fuzz}}",
                          "error_based": True, "time_based": False, "timeout": 3},
                         sample_context)
        finally:
            app.close()
        assert any(f["kind"] == "error-based" for f in res["findings"])
        err = next(f for f in res["findings"] if f["kind"] == "error-based")
        assert "mysql" in err["db_engine"] or "generic" in err["db_engine"]
        assert err["parameter"] == "url-slot"

    def test_query_param_scan(self, sample_context):
        app = _App()
        try:
            res = sq.run({"target_url": f"http://127.0.0.1:{app.port}/item?id=1",
                          "error_based": True, "time_based": False,
                          "timeout": 3}, sample_context)
        finally:
            app.close()
        assert any(f["parameter"] == "id" for f in res["findings"])