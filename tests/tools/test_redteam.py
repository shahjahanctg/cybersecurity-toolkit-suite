"""Tests for metasploit-module (+ c2 tools + persistence-rules)."""

from __future__ import annotations

import pytest

from sectoolkit.tools.redteam import (metasploit_module as mm,
                                      c2_obfuscation as co,
                                      c2_jitter as cj,
                                      persistence_rules as pr)


class TestMetasploitModule:
    def test_meta(self):
        m = mm.TOOL
        assert m.wave == 7 and m.mode == "read"

    def test_generates_auxiliary(self, sample_context):
        res = mm.run({"module_name": "lab_probe", "module_type": "auxiliary"},
                     sample_context)
        assert res["module_name"] == "lab_probe"
        assert "Msf::Auxiliary" in res["ruby_code"]
        assert "Msf::Exploit::Remote::Tcp" in res["ruby_code"]
        assert "127\\.0\\.0\\.1" not in res["ruby_code"]

    def test_generates_exploit(self, sample_context):
        res = mm.run({"module_name": "lab_bof", "module_type": "exploit"},
                     sample_context)
        assert "Msf::Exploit" in res["ruby_code"]
        assert "payload.encoded" in res["ruby_code"]

    def test_bad_type(self, sample_context):
        with pytest.raises(ValueError, match="module_type"):
            mm.run({"module_type": "scanner"}, sample_context)

    def test_writes_rb(self, sample_context, tmp_path):
        out = tmp_path / "mod.rb"
        res = mm.run({"module_name": "x_mod", "module_type": "post",
                      "output_file": str(out)}, sample_context)
        assert res["output_file"] == str(out)
        assert "Msf::Post" in out.read_text()


class TestC2Obfuscation:
    def test_meta(self):
        m = co.TOOL
        assert m.wave == 7 and m.mode == "read"

    def test_empty_marker(self, sample_context):
        with pytest.raises(ValueError, match="marker"):
            co.run({"marker": ""}, sample_context)

    def test_xor_roundtrip(self, sample_context):
        res = co.run({"marker": "pulse check-in", "method": "xor",
                      "key": "k"}, sample_context)
        to_bytes = co._xor_encode(b"pulse check-in", b"k")
        deobf = co._xor_encode(to_bytes, b"k")
        assert deobf == b"pulse check-in"
        assert res["obfuscated_bytes"] == len(to_bytes)

    def test_base64(self, sample_context):
        import base64
        res = co.run({"marker": "hello", "method": "base64"}, sample_context)
        assert base64.b64decode(co._obfuscate(b"hello", "base64", b"k")["body"]) \
            == b"hello"
        assert res["method"] == "base64"

    def test_writes_files(self, sample_context, tmp_path):
        out = tmp_path / "out"
        res = co.run({"marker": "beacon", "method": "xor-base64",
                      "output_dir": str(out)}, sample_context)
        assert (out / "payload.bin").exists()
        assert (out / "deobfuscator.py").exists()


class TestC2Jitter:
    def test_meta(self):
        m = cj.TOOL
        assert m.wave == 7 and m.mode == "read"

    def test_bounds(self, sample_context):
        res = cj.run({"sleep_base": 60, "jitter_percent": 20,
                      "iterations": 5}, sample_context)
        assert res["delay_min_s"] == 48.0
        assert res["delay_max_s"] == 72.0
        assert len(res["timeline"]) == 5
        assert all(48.0 <= t["delay_s"] <= 72.0 for t in res["timeline"])

    def test_bad_jitter(self, sample_context):
        with pytest.raises(ValueError, match="jitter"):
            cj.run({"jitter_percent": 120}, sample_context)

    def test_writes_csv(self, sample_context, tmp_path):
        out = tmp_path / "t"
        res = cj.run({"sleep_base": 30, "jitter_percent": 10,
                      "iterations": 3, "output_dir": str(out)}, sample_context)
        csv = (out / "beacon-timeline.csv").read_text()
        assert csv.startswith("iter,delay_s,elapsed_s")
        assert csv.count("\n") == 3


class TestPersistenceRules:
    def test_meta(self):
        m = pr.TOOL
        assert m.wave == 7 and m.mode == "read"

    def test_requires_input(self, sample_context):
        with pytest.raises(ValueError, match="catalog_json|root"):
            pr.run({}, sample_context)

    def test_catalog_to_rules(self, sample_context, tmp_path):
        import json
        cat = tmp_path / "cat.json"
        cat.write_text(json.dumps({
            "findings": [{"kind": "registry-run", "path": "hive.reg",
                          "detail": "evil = cmd.exe"},
                         {"kind": "systemd-unit", "path": "evil.service",
                          "detail": "ExecStart=/tmp/x"}]}))
        out = tmp_path / "rules"
        res = pr.run({"catalog_json": str(cat), "output_dir": str(out)},
                     sample_context)
        assert res["rules_count"] == 2
        assert len(list(out.glob("*.yml"))) == 2
        first = (sorted(out.glob("*.yml"))[0]).read_text()
        assert "title:" in first and "detection:" in first