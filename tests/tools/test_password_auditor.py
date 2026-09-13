"""Tests for the password auditor + cracker."""

from __future__ import annotations

import hashlib

import pytest

from sectoolkit.tools.vulnscan import password_auditor as pa


class TestAudit:
    def test_meta(self):
        m = pa.TOOL
        assert m.wave == 4 and m.mode == "read"
        assert m.category == "vulnscan"

    def test_weak_common_password(self, sample_context):
        res = pa.run({"mode": "audit", "password": "password123"}, sample_context)
        a = res["audit"]
        assert a["verdict"] in ("weak", "ok")
        assert any(c["check"] == "well-known" and not c["ok"] for c in a["checks"])

    def test_strong_password(self, sample_context):
        res = pa.run({"mode": "audit",
                      "password": "Tr0ub4dor&3-XyZ9!q7"}, sample_context)
        a = res["audit"]
        assert a["verdict"] == "strong"
        assert a["score"] >= 8

    def test_missing_password(self, sample_context):
        with pytest.raises(ValueError, match="password"):
            pa.run({"mode": "audit"}, sample_context)


class TestCrack:
    def test_crack_admin123_md5(self, sample_context):
        h = hashlib.md5(b"admin123").hexdigest()
        res = pa.run({"mode": "crack", "hash_input": h}, sample_context)
        assert res["cracked_count"] == 1
        assert res["uncracked_count"] == 0
        assert res["cracked"][0]["plaintext"] == "admin123"
        assert res["cracked"][0]["format"] == "md5"

    def test_crack_with_salt(self, sample_context):
        salt = bytes.fromhex("a1b2")
        h = hashlib.sha256(salt + b"letmein").hexdigest()
        res = pa.run({"mode": "crack", "hash_input": f"{h}:sha256",
                      "salt": "a1b2"}, sample_context)
        assert any(c["plaintext"] == "letmein" for c in res["cracked"])

    def test_crack_multiple_and_uncracked(self, sample_context):
        h1 = hashlib.md5(b"letmein").hexdigest()
        h2 = hashlib.sha1(b"unfindable").hexdigest()
        res = pa.run({"mode": "crack",
                      "hash_input": f"{h1}\n{h2}"}, sample_context)
        assert res["cracked_count"] == 1
        assert res["uncracked_count"] == 1

    def test_missing_hash_input(self, sample_context):
        with pytest.raises(ValueError, match="hash_input"):
            pa.run({"mode": "crack"}, sample_context)

    def test_bad_hash(self, sample_context):
        with pytest.raises(ValueError, match="hex"):
            pa.run({"mode": "crack", "hash_input": "zzzz"}, sample_context)