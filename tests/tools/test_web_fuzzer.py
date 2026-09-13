"""Tests for the web fuzzer (gating + discovery against a live origin)."""

from __future__ import annotations

import socket
import threading
import time

import pytest

from sectoolkit.tools.vulnscan import web_fuzzer as wf


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _Origin:
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
        from urllib.parse import urlparse
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
            path = data.split(b" ")[1].decode("latin-1", "replace")
            if path in ("/", "/index.php", "/robots.txt"):
                body = b"ok" + path.encode()
                status = b"200 OK"
            else:
                body = b"not found"
                status = b"404 Not Found"
            c.sendall(b"HTTP/1.1 " + status + b"\r\nContent-Length: " +
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
        m = wf.TOOL
        assert m.wave == 4 and m.category == "vulnscan" and m.mode == "act"

    def test_bad_scheme(self, sample_context):
        with pytest.raises(ValueError, match="http"):
            wf.run({"target_url": "ftp://127.0.0.1/"},
                   sample_context)


class TestDiscovery:
    def test_finds_existing_paths(self, sample_context, tmp_path):
        origin = _Origin()
        wordlist = tmp_path / "wl.txt"
        wordlist.write_text("index.php\nrobots.txt\nmissing.php\n",
                            encoding="utf-8")
        try:
            res = wf.run({"target_url": f"http://127.0.0.1:{origin.port}/",
                          "wordlist": str(wordlist), "threads": 4,
                          "timeout": 3}, sample_context)
        finally:
            origin.close()
        assert res["paths_tested"] == 3
        found = {r["url"] for r in res["results"]}
        assert f"http://127.0.0.1:{origin.port}/index.php" in found
        assert f"http://127.0.0.1:{origin.port}/robots.txt" in found
        assert all(r["status"] in (200,) for r in res["results"])
        assert res["status_counts"].get("200") == 2

    def test_empty_wordlist(self, sample_context, tmp_path):
        empty = tmp_path / "empty.txt"
        empty.write_text("# nothing\n")
        with pytest.raises(ValueError, match="wordlist"):
            wf.run({"target_url": "http://127.0.0.1:9/",
                    "wordlist": str(empty)}, sample_context)