"""Tests for memory-forensics (vol wrapper + strings mode)."""

from __future__ import annotations

import json
import textwrap

import pytest

from sectoolkit.tools.forensics import memory_forensics as mf


class TestStrings:
    def test_meta(self):
        m = mf.TOOL
        assert m.wave == 5 and m.category == "forensics"
        assert m.mode == "read"

    def test_extracts_strings(self, sample_context, tmp_path):
        dump = tmp_path / "mem.bin"
        dump.write_bytes(b"\x00\x01" + b"process.exec.payload" +
                         b"\x00" + b"C:\\Windows\\System32\\evil.exe" + b"\x00")
        res = mf.run({"image": str(dump), "mode": "strings"}, sample_context)
        assert "process.exec.payload" in res["strings"]
        assert "C:\\Windows\\System32\\evil.exe" in res["strings"]

    def test_missing_image(self, sample_context):
        with pytest.raises(ValueError, match="image"):
            mf.run({}, sample_context)

    def test_nonexistent_image(self, sample_context):
        with pytest.raises(ValueError, match="does not exist"):
            mf.run({"image": "/nope.bin"}, sample_context)

    def test_writes_strings_file(self, sample_context, tmp_path):
        dump = tmp_path / "r.dmp"
        dump.write_bytes(b"\x00thread-id-99\x00")
        out = tmp_path / "out"
        res = mf.run({"image": str(dump), "mode": "strings",
                      "output_dir": str(out)}, sample_context)
        assert res["output_file"].endswith(".strings.txt")
        assert "thread-id-99" in out.joinpath("r.dmp.strings.txt").read_text()


class TestVol:
    def test_missing_binary(self, sample_context, tmp_path):
        dump = tmp_path / "m.dmp"
        dump.write_bytes(b"x" * 4)
        with pytest.raises(RuntimeError, match="volatility"):
            mf.run({"image": str(dump), "mode": "vol",
                    "vol_binary": "definitely-not-a-binary"}, sample_context)

    def test_runs_plugin(self, sample_context, tmp_path):
        dump = tmp_path / "m.dmp"
        dump.write_bytes(b"x" * 4)
        fake = tmp_path / "fakevol"
        fake.write_text(textwrap.dedent("""\
            #!/usr/bin/env python3
            import json, sys
            json.dump([{"PID": 1, "ImageFileName": "svchost.exe"}], sys.stdout)
        """))
        fake.chmod(0o755)
        res = mf.run({"image": str(dump), "mode": "vol",
                      "vol_binary": str(fake)}, sample_context)
        assert res["records"] == 1
        assert "svchost.exe" in res["report"]