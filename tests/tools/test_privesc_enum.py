"""Tests for privesc-enum."""

from __future__ import annotations

import stat

import pytest

from sectoolkit.tools.redteam import privesc_enum as pe


class TestEnum:
    def test_meta(self):
        m = pe.TOOL
        assert m.wave == 7 and m.category == "redteam"
        assert m.mode == "read"

    def test_scans_suid_from_fixture(self, sample_context, tmp_path, monkeypatch):
        from pathlib import Path
        bindir = tmp_path / "usr" / "bin"
        bindir.mkdir(parents=True)
        suid = bindir / "openssl"
        suid.touch()
        suid.chmod(0o6755)
        normal = bindir / "ls"
        normal.touch()
        normal.chmod(0o755)
        monkeypatch.setattr(pe, "_BIN_DIRS", [str(bindir)])
        monkeypatch.setattr("platform.system", lambda: "Linux")
        res = pe.run({"scan_bins": True}, sample_context)
        suid_findings = [f for f in res["findings"] if f["kind"] == "SUID binary"]
        assert any(f["path"] == str(suid) for f in suid_findings)
        assert all("ls" not in f["path"] for f in suid_findings)

    def test_non_linux_note(self, sample_context, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: "Windows")
        monkeypatch.setattr("platform.platform", lambda: "win32-x")
        res = pe.run({}, sample_context)
        assert any(f["kind"] == "platform" for f in res["findings"])