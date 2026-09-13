"""Tests for c2-extractor."""

from __future__ import annotations

import pytest

from sectoolkit.tools.malware import c2_extractor as c2


class TestExtract:
    def test_meta(self):
        m = c2.TOOL
        assert m.wave == 6 and m.category == "malware"
        assert m.mode == "read"

    def test_missing_sample(self, sample_context):
        with pytest.raises(ValueError, match="sample"):
            c2.run({}, sample_context)

    def test_extracts_candidates(self, sample_context, tmp_path):
        data = (b"user-agent: Mozilla/4.0 beacon jitter=120 sleep=60 "
                b"http://c2.badexample.net/beacon/v2 "
                b"https://203.0.113.9:443/x")
        sample = tmp_path / "dmp.bin"
        sample.write_bytes(data)
        res = c2.run({"sample": str(sample)}, sample_context)
        assert "c2.badexample.net" in res["domains"]
        assert any("203.0.113.9" in ip for ip in res["ip_literals"])
        assert {"parameter": "jitter", "value": 120} in res["timings"]
        assert any("user-agent" in r.lower() for r in res["http_remnants"])

    def test_private_ips_filter(self, sample_context, tmp_path):
        sample = tmp_path / "p.bin"
        sample.write_bytes(b"http://10.0.0.5/xz")
        res = c2.run({"sample": str(sample)}, sample_context)
        assert res["ip_literals"] == []
        res = c2.run({"sample": str(sample),
                      "include_private_ips": True}, sample_context)
        assert "10.0.0.5" in res["ip_literals"]

    def test_writes_json(self, sample_context, tmp_path):
        import json
        sample = tmp_path / "j.bin"
        sample.write_bytes(b"c2.example1.net carrier pigeon")
        out = tmp_path / "c2.json"
        res = c2.run({"sample": str(sample), "output_file": str(out)},
                     sample_context)
        assert res["output_file"] == str(out)
        report = json.loads(out.read_text())
        assert "c2.example1.net" in report["domains"]