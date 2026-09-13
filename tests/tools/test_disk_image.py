"""Tests for the disk-image chain-of-custody tool."""

from __future__ import annotations

import hashlib
import json

import pytest

from sectoolkit.tools.forensics import disk_image as di


def _mk_image(tmp_path, payload: bytes):
    p = tmp_path / "disk.img"
    p.write_bytes(payload)
    return p


class TestHash:
    def test_meta(self):
        m = di.TOOL
        assert m.wave == 5 and m.category == "forensics"
        assert m.mode == "read"

    def test_missing_input(self, sample_context):
        with pytest.raises(ValueError, match="input"):
            di.run({}, sample_context)

    def test_nonexistent_input(self, sample_context):
        with pytest.raises(ValueError, match="does not exist"):
            di.run({"input": "/nope.bin"}, sample_context)

    def test_hashes(self, sample_context, tmp_path):
        payload = b"the quick brown fox jumps over the lazy dog" * 500
        img = _mk_image(tmp_path, payload)
        res = di.run({"input": str(img), "mode": "hash", "investigator": "test"},
                     sample_context)
        assert res["sha256"] == hashlib.sha256(payload).hexdigest()
        assert res["sha1"] == hashlib.sha1(payload).hexdigest()
        assert res["size_bytes"] == len(payload)


class TestVerify:
    def test_ok(self, sample_context, tmp_path):
        payload = b"verify me" * 100
        img = _mk_image(tmp_path, payload)
        res = di.run({"input": str(img), "mode": "verify",
                      "expected_sha256": hashlib.sha256(payload).hexdigest()},
                     sample_context)
        assert res["verified_ok"] is True

    def test_mismatch(self, sample_context, tmp_path):
        img = _mk_image(tmp_path, b"a" * 50)
        res = di.run({"input": str(img), "mode": "verify",
                      "expected_sha256": hashlib.sha256(b"b" * 50).hexdigest()},
                     sample_context)
        assert res["verified_ok"] is False

    def test_requires_expected(self, sample_context, tmp_path):
        img = _mk_image(tmp_path, b"x" * 10)
        with pytest.raises(ValueError, match="expected_sha256"):
            di.run({"input": str(img), "mode": "verify"}, sample_context)


class TestImage:
    def test_copies_and_writes_custody(self, sample_context, tmp_path):
        payload = b"chain of custody" * 100
        src = _mk_image(tmp_path, payload)
        out = tmp_path / "case"
        res = di.run({"input": str(src), "mode": "image",
                      "output_dir": str(out), "investigator": "det. k",
                      "case_id": "C-1"}, sample_context)
        assert res["src_sha256"] == res["dst_sha256"] == \
            hashlib.sha256(payload).hexdigest()
        assert (out / "disk.img.img").read_bytes() == payload
        cust = json.loads((out / "disk.img.img.custody.json").read_text())
        assert cust["investigator"] == "det. k"
        assert cust["case_id"] == "C-1"
        assert cust["src_sha256"] == cust["dst_sha256"]