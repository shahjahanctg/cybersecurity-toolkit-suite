"""Tests for buffer-overflow walkthrough."""

from __future__ import annotations

import pytest

from sectoolkit.tools.redteam import buffer_overflow as bo


class TestWalkthrough:
    def test_meta(self):
        m = bo.TOOL
        assert m.wave == 7 and m.category == "redteam"

    def test_walkthrough_mode(self, sample_context):
        res = bo.run({"mode": "walkthrough"}, sample_context)
        assert "Stack overflow walkthrough" in res["guide"]


class TestCyclic:
    def test_pattern_has_unique_triples(self, sample_context):
        res = bo.run({"mode": "cyclic", "length": 300}, sample_context)
        assert len(res["pattern"]) == 300
        # first two triples differ (cycle quality is structural)
        assert res["pattern"][:3] != res["pattern"][3:6]


class TestPayload:
    def test_layout(self, sample_context):
        res = bo.run({"mode": "payload", "offset": 100,
                      "return_address": "\\x11\\x22\\x33\\x44",
                      "bad_chars": "\\x00\\x0a", "shellcode_size": 64},
                     sample_context)
        assert res["junk_bytes"] == 100
        assert res["payload_size"] == 100 + 4 + 16 + 64
        assert res["bad_chars"] == [0, 10]

    def test_badchar_in_ret_rejected(self, sample_context):
        with pytest.raises(ValueError, match="bad character"):
            bo.run({"mode": "payload", "offset": 64,
                    "return_address": "\\x00\\x22\\x33\\x44",
                    "bad_chars": "\\x00", "shellcode_size": 32},
                   sample_context)

    def test_writes_payload(self, sample_context, tmp_path):
        out = tmp_path / "p"
        res = bo.run({"mode": "payload", "offset": 10,
                      "output_dir": str(out)}, sample_context)
        assert (out / "payload.bin").exists()
        assert len((out / "payload.bin").read_bytes()) == res["payload_size"]