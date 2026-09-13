"""Tests for persistence-catalog."""

from __future__ import annotations

import pytest

from sectoolkit.tools.malware import persistence_catalog as pc


class TestScan:
    def test_meta(self):
        m = pc.TOOL
        assert m.wave == 6 and m.category == "malware"
        assert m.mode == "read"

    def test_missing_root(self, sample_context):
        with pytest.raises(ValueError, match="root"):
            pc.run({}, sample_context)

    def test_finds_startup_and_systemd(self, sample_context, tmp_path):
        tree = tmp_path / "fs"
        (tree / "home/u/.config/autostart").mkdir(parents=True)
        (tree / "etc/systemd/system").mkdir(parents=True)
        (tree / "etc/init.d").mkdir(parents=True)
        (tree / "etc/systemd/system" / "evil.service").write_text(
            "[Service]\nExecStart=/bin/evil --persist\n")
        (tree / "etc/init.d" / "evil").write_text("#!/bin/sh\nevil &\n")
        (tree / "home/u/.config/autostart" / "payload.desktop").write_text(
            "[Desktop Entry]\nExec=/tmp/payload\n")
        res = pc.run({"root": str(tree)}, sample_context)
        kinds = {f["kind"] for f in res["findings"]}
        assert "systemd-unit" in kinds
        assert "init-script" in kinds
        assert "autostart" in kinds
        assert any("/bin/evil --persist" in f["detail"]
                   for f in res["findings"])

    def test_cron_lines(self, sample_context, tmp_path):
        tree = tmp_path / "cr"
        (tree / "etc/cron.d").mkdir(parents=True)
        (tree / "etc/cron.d" / "x").write_text(
            "*/5 * * * * root /bin/beacon every5\n")
        res = pc.run({"root": str(tree)}, sample_context)
        assert any(f["kind"] == "cron" and "/bin/beacon every5" in f["detail"]
                   for f in res["findings"])

    def test_registry_run(self, sample_context, tmp_path):
        tree = tmp_path / "reg"
        tree.mkdir(exist_ok=True)
        (tree / "hive.reg").write_text(
            '[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\'
            'CurrentVersion\\Run]\n"Malware"="C:\\\\Users\\\\x\\\\evil.exe"\n')
        res = pc.run({"root": str(tree)}, sample_context)
        assert any(f["kind"] == "registry-run" and "evil.exe" in f["detail"]
                   for f in res["findings"])