"""Tests for yara-rulegen."""

from __future__ import annotations

import re

import pytest

from sectoolkit.tools.malware import yara_rulegen as yg


class TestGenerate:
    def test_meta(self):
        m = yg.TOOL
        assert m.wave == 6 and m.category == "malware"
        assert m.mode == "read"

    def test_generates_rule(self, sample_context, tmp_path):
        sample = tmp_path / "mal.exe"
        sample.write_bytes(b"x" * 10 +
                           b"uniquec2domain.example.net callhome47runkey " * 3)
        res = yg.run({"sample": str(sample), "rule_name": "my_rule"},
                     sample_context)
        assert res["mode"] == "generate"
        assert "rule my_rule" in res["rule_text"]
        assert "uniquec2domain.example.net" in res["rule_text"]
        assert "$s0 =" in res["rule_text"]
        assert "any of them" in res["rule_text"]

    def test_writes_yar(self, sample_context, tmp_path):
        sample = tmp_path / "m.bin"
        sample.write_bytes(b"AAAA phonehome456 BBBB")
        out = tmp_path / "rule.yar"
        res = yg.run({"sample": str(sample), "output_file": str(out)},
                     sample_context)
        assert res["output_file"] == str(out)
        assert out.read_text().startswith("rule ")

    def test_sanitizes_name(self, sample_context, tmp_path):
        sample = tmp_path / "weird name!.bin"
        sample.write_bytes(b"AAAA1234 BBBB")
        res = yg.run({"sample": str(sample)}, sample_context)
        assert re.fullmatch(r"rule[a-z0-9_]+", res["rule_name"])


class TestClassify:
    def test_classify_tags_and_match(self, sample_context, tmp_path):
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"UPX! \x00 CreateRemoteThread lsass "
                           b"physealcheckvalue http://c2.example.com/x")
        rule = tmp_path / "r.yar"
        rule.write_text('rule r { strings: $a = "physealcheckvalue" '
                        '$b = "missingone" condition: any of them }')
        res = yg.run({"sample": str(sample), "mode": "classify",
                      "rule_file": str(rule)}, sample_context)
        assert "UPX packed" in res["tags"]
        assert "Windows API heavy" in res["tags"]
        assert "physealcheckvalue" in res["rule_strings_present"]
        assert "missingone" not in res["rule_strings_present"]