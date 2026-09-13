"""Tests for unpack-tool (detect + decode)."""

from __future__ import annotations

import base64
import gzip
import zlib

import pytest

from sectoolkit.tools.malware import unpack_tool as ut


class TestDetect:
    def test_meta(self):
        m = ut.TOOL
        assert m.wave == 6 and m.category == "malware"
        assert m.mode == "read"

    def test_detects_layers(self, sample_context, tmp_path):
        payload = base64.b64encode(b"the quick brown fox jumped" * 5)
        data = b"\x00\x00" + payload + b"\x00\x1f\x8b\x08\x00"
        sample = tmp_path / "mixed.bin"
        sample.write_bytes(data)
        res = ut.run({"sample": str(sample), "mode": "detect"}, sample_context)
        names = [l["name"] for l in res["layers"]]
        assert "base64" in names and "gzip" in names

    def test_missing_sample(self, sample_context):
        with pytest.raises(ValueError, match="sample"):
            ut.run({}, sample_context)


class TestDecode:
    def test_base64_layer(self, sample_context, tmp_path):
        blob = base64.b64encode(b"secret clear text payload")
        sample = tmp_path / "b.bin"
        sample.write_bytes(b"\x00" + blob)
        out = tmp_path / "out"
        res = ut.run({"sample": str(sample), "mode": "decode",
                      "layer": "base64", "output_dir": str(out)},
                     sample_context)
        assert res["decoded_bytes"] == len(b"secret clear text payload")
        assert (out / "b.bin.base64.decoded").read_bytes() == \
            b"secret clear text payload"

    def test_gzip_layer(self, sample_context, tmp_path):
        sample = tmp_path / "g.bin"
        sample.write_bytes(gzip.compress(b"gunzipped body" * 20))
        res = ut.run({"sample": str(sample), "mode": "decode",
                      "layer": "gzip"}, sample_context)
        assert res["decoded_bytes"] == len(b"gunzipped body" * 20)

    def test_zlib_layer(self, sample_context, tmp_path):
        sample = tmp_path / "z.bin"
        sample.write_bytes(zlib.compress(b"inflate me me me" * 10))
        res = ut.run({"sample": str(sample), "mode": "decode",
                      "layer": "zlib"}, sample_context)
        assert res["decoded_bytes"] == len(b"inflate me me me" * 10)

    def test_xor_roundtrip(self, sample_context, tmp_path):
        sample = tmp_path / "x.bin"
        sample.write_bytes(bytes(b ^ 0x55 for b in b"cleartext xor demo" * 4))
        res = ut.run({"sample": str(sample), "mode": "decode",
                      "layer": "xor"}, sample_context)
        assert b"cleartext xor demo" in res["decoded_preview"]

    def test_upx_decode_refused(self, sample_context, tmp_path):
        sample = tmp_path / "up.bin"
        sample.write_bytes(b"UPX! payload")
        with pytest.raises(ValueError, match="upx"):
            ut.run({"sample": str(sample), "mode": "decode",
                    "layer": "upx-header"}, sample_context)