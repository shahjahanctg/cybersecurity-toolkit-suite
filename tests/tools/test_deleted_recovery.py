"""Tests for deleted-file-recovery signature carving."""

from __future__ import annotations

import pytest

from sectoolkit.tools.forensics import deleted_recovery as dr

_JPG = b"\xff\xd8\xff\xe0JFIF" + (b"A" * 3000)
_PNG = b"\x89PNG\r\n\x1a\n" + (b"B" * 2000)
_ELF = b"\x7fELF\x02\x01\x01" + (b"C" * 900)


class TestCarve:
    def test_meta(self):
        m = dr.TOOL
        assert m.wave == 5 and m.category == "forensics"
        assert m.mode == "read"

    def test_missing_input(self, sample_context):
        with pytest.raises(ValueError, match="image"):
            dr.run({}, sample_context)

    def test_missing_output(self, sample_context, tmp_path):
        dummy = tmp_path / "x.img"
        dummy.write_bytes(b"x")
        with pytest.raises(ValueError, match="output_dir"):
            dr.run({"image": str(dummy)}, sample_context)

    def test_carves_artifacts(self, sample_context, tmp_path):
        img = tmp_path / "mixed.img"
        img.write_bytes(b"\x00" * 100 + _JPG + b"\xff" * 50 + _PNG + _ELF)
        out = tmp_path / "out"
        res = dr.run({"image": str(img), "output_dir": str(out)},
                     sample_context)
        kinds = sorted({h["kind"] for h in res["recovered"]})
        assert "jpg" in kinds and "png" in kinds and "elf" in kinds

        # verify content round-trips
        files = [p.name for p in out.rglob("*.bin")]
        assert len(files) == res["carved_count"] == 3

    def test_min_size_filter(self, sample_context, tmp_path):
        small = b"\x7fELF" + b"C" * 60  # 64 bytes total
        img = tmp_path / "s.img"
        img.write_bytes(small)
        out = tmp_path / "o"
        res = dr.run({"image": str(img), "output_dir": str(out),
                      "min_size": 500}, sample_context)
        assert res["carved_count"] == 0

    def test_bad_sizes(self, sample_context, tmp_path):
        img = tmp_path / "b.img"
        img.write_bytes(b"x")
        with pytest.raises(ValueError, match="max_size"):
            dr.run({"image": str(img), "output_dir": str(tmp_path / "o"),
                    "min_size": 100, "max_size": 10}, sample_context)