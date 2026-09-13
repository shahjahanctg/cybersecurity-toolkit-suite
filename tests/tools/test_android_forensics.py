"""Tests for android-forensics (.ab backup parser)."""

from __future__ import annotations

import io
import tarfile
import zlib

import pytest

from sectoolkit.tools.forensics import android_forensics as af


def _make_ab(files: dict, compress: bool = True) -> bytes:
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as tar:
        for name, content in files.items():
            data = io.BytesIO(content.encode())
            info = tarfile.TarInfo("apps/com.example/f/" + name)
            info.size = len(content)
            tar.addfile(info, data)
    tar_bytes = bio.getvalue()
    payload = zlib.compress(tar_bytes) if compress else tar_bytes
    header = (b"ANDROID BACKUP\n1\n1\n%d\n(none)\n" % (1 if compress else 0))
    return header + payload


class TestParse:
    def test_meta(self):
        m = af.TOOL
        assert m.wave == 5 and m.category == "forensics"
        assert m.mode == "read"

    def test_missing_backup(self, sample_context):
        with pytest.raises(ValueError, match="backup"):
            af.run({}, sample_context)

    def test_bad_magic(self, sample_context, tmp_path):
        bad = tmp_path / "bad.ab"
        bad.write_bytes(b"NOT A BACKUP\n")
        with pytest.raises(ValueError, match="not an Android backup"):
            af.run({"backup": str(bad)}, sample_context)

    def test_list_entries(self, sample_context, tmp_path):
        ab = tmp_path / "dev.ab"
        ab.write_bytes(_make_ab({"notes.txt": "hello", "db.db": "sqlite"}))
        res = af.run({"backup": str(ab), "mode": "list"}, sample_context)
        names = {e["path"] for e in res["entries"]}
        assert "apps/com.example/f/notes.txt" in names
        assert "apps/com.example/f/db.db" in names
        assert res["entry_count"] == 2

    def test_extract(self, sample_context, tmp_path):
        ab = tmp_path / "dev.ab"
        ab.write_bytes(_make_ab({"notes.txt": "hello android"}))
        out = tmp_path / "extract"
        res = af.run({"backup": str(ab), "mode": "extract",
                      "output_dir": str(out)}, sample_context)
        assert res["extracted_files"]
        assert (out / "notes.txt").read_text() == "hello android"

    def test_uncompressed_backup(self, sample_context, tmp_path):
        ab = tmp_path / "raw.ab"
        ab.write_bytes(_make_ab({"a.txt": "raw"}, compress=False))
        res = af.run({"backup": str(ab)}, sample_context)
        assert res["compressed"] is False
        assert res["entry_count"] == 1

    def test_encrypted_refused(self, sample_context, tmp_path):
        ab = tmp_path / "enc.ab"
        ab.write_bytes(b"ANDROID BACKUP\n1\n1\n1\nAES-256\n" + b"\x00" * 16)
        with pytest.raises(ValueError, match="encrypted"):
            af.run({"backup": str(ab)}, sample_context)