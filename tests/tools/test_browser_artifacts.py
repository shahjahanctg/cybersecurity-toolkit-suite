"""Tests for browser-artifacts (Firefox profile sqlite parsing)."""

from __future__ import annotations

import json
import sqlite3

import pytest

from sectoolkit.tools.forensics import browser_artifacts as ba


def _ff_profile(path):
    path.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path / "places.sqlite")
    con.execute("CREATE TABLE moz_places (url TEXT, title TEXT, "
                "visit_count INTEGER, last_visit_date INTEGER)")
    con.execute("INSERT INTO moz_places VALUES (?,?,?,?)",
                ("https://example.com/a", "Example A", 3, 1700000000000000))
    con.commit()
    con.close()
    con = sqlite3.connect(path / "cookies.sqlite")
    con.execute("CREATE TABLE moz_cookies (name TEXT, host TEXT, path TEXT, "
                "value TEXT, creationTime INT, expiry INT)")
    con.execute("INSERT INTO moz_cookies VALUES (?,?,?,?,?,?)",
                ("session", ".example.com", "/", "abc", 1, 2))
    con.commit()
    con.close()
    return path


class TestFirefox:
    def test_meta(self):
        m = ba.TOOL
        assert m.wave == 5 and m.category == "forensics"
        assert m.mode == "read"

    def test_missing_profile(self, sample_context):
        with pytest.raises(ValueError, match="profile_dir"):
            ba.run({}, sample_context)

    def test_extracts_history_and_cookies(self, sample_context, tmp_path):
        prof = _ff_profile(tmp_path / "prof")
        res = ba.run({"profile_dir": str(prof)}, sample_context)
        urls = [r for r in res["rows"] if r["kind"] == "url"]
        cookies = [r for r in res["rows"] if r["kind"] == "cookie"]
        assert any(u["url"] == "https://example.com/a" for u in urls)
        assert any(c["host"] == ".example.com" and c["name"] == "session"
                   for c in cookies)

    def test_writes_json(self, sample_context, tmp_path):
        prof = _ff_profile(tmp_path / "p2")
        out = tmp_path / "report.json"
        res = ba.run({"profile_dir": str(prof),
                      "output_file": str(out)}, sample_context)
        assert res["output_file"] == str(out)
        report = json.loads(out.read_text())
        assert report["browser"] == "firefox"

    def test_unreadable_profile(self, sample_context, tmp_path):
        empty = tmp_path / "nope"
        empty.mkdir()
        with pytest.raises(ValueError, match="cannot detect"):
            ba.run({"profile_dir": str(empty)}, sample_context)