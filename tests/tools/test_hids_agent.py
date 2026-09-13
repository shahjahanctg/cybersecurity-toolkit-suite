"""Tests for the HIDS agent (baseline/check/processes on real temp trees)."""

from __future__ import annotations

import pytest

from sectoolkit.tools.defense import hids_agent as hids


class TestScan:
    def test_baseline_than_check_no_changes(self, sample_context, tmp_path):
        (tmp_path / "a.txt").write_text("hello")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "b.txt").write_text("world")

        base_result = hids.run({"mode": "baseline", "paths": str(tmp_path),
                                "baseline": str(tmp_path / "base.json")}, sample_context)
        assert base_result["files_recorded"] == 2

        check = hids.run({"mode": "check", "paths": str(tmp_path),
                          "baseline": str(tmp_path / "base.json")}, sample_context)
        assert check["integrity"] == "CLEAN"
        assert check["added"] == [] and check["removed"] == [] and check["modified"] == []

    def test_check_detects_all_change_classes(self, sample_context, tmp_path):
        (tmp_path / "keep.txt").write_text("same")
        (tmp_path / "victim.txt").write_text("original")
        base = str(tmp_path / "base.json")
        hids.run({"mode": "baseline", "paths": str(tmp_path), "baseline": base}, sample_context)

        (tmp_path / "victim.txt").write_text("tampered")
        (tmp_path / "new.txt").write_text("added")
        (tmp_path / "keep.txt").unlink()

        check = hids.run({"mode": "check", "paths": str(tmp_path), "baseline": base}, sample_context)
        assert check["integrity"] == "CHANGED"
        assert check["modified"][0]["path"].endswith("victim.txt")
        assert check["added"] == ["new.txt"]
        assert check["removed"] == ["keep.txt"]

    def test_exclusions_skipped(self, sample_context, tmp_path):
        (tmp_path / "secret_key.pem").write_text("x")
        (tmp_path / "ok.txt").write_text("y")
        result = hids.run({"mode": "baseline", "paths": str(tmp_path),
                           "baseline": str(tmp_path / "base.json"),
                           "exclusions": ".pem"}, sample_context)
        assert result["files_recorded"] == 1

    def test_missing_path_raises(self, sample_context):
        with pytest.raises(ValueError, match="does not exist"):
            hids.run({"mode": "baseline", "paths": "/nonexistent-xyz"},
                     sample_context)

    def test_symlink_skipped(self, sample_context, tmp_path):
        (tmp_path / "t.txt").write_text("x")
        target = tmp_path / "target.txt"
        target.write_text("y")
        try:
            (tmp_path / "link.txt").symlink_to(target)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not supported here")
        result = hids.run({"mode": "baseline", "paths": str(tmp_path),
                           "baseline": str(tmp_path / "base.json")}, sample_context)
        assert result["files_recorded"] == 2  # link itself excluded

    def test_check_without_baseline_raises_clear(self, sample_context, tmp_path):
        (tmp_path / "a.txt").write_text("x")
        with pytest.raises(ValueError, match="baseline"):
            hids.run({"mode": "check", "paths": str(tmp_path)}, sample_context)


class TestDiff:
    def test_diff_states(self):
        base = {"a": {"sha256": "1", "size": 1, "mtime": 1}}
        now = {"a": {"sha256": "2", "size": 1, "mtime": 9}, "b": {"sha256": "3", "size": 1, "mtime": 1}}
        report = hids.diff_states(base, now)
        assert report["modified"][0]["path"] == "a"
        assert report["added"] == ["b"]

    def test_render_clean(self):
        text = hids.render({"mode": "check", "integrity": "CLEAN", "scanned_files": 5, "duration_ms": 3})
        assert "CLEAN" in text and "No changes" in text


class TestMeta:
    def test_meta(self):
        m = hids.TOOL
        assert m.wave == 2 and m.category == "defense" and m.mode == "read"
        assert {f.name for f in m.fields} >= {"mode", "paths", "baseline", "exclusions"}

    def test_process_snapshot_shape(self):
        # runs only on Linux; on other platforms it must raise a clear error
        import platform
        if platform.system() != "Linux":
            with pytest.raises(ValueError):
                hids.process_snapshot()
        else:
            procs = hids.process_snapshot()
            assert procs and all({"pid", "comm", "state", "uid", "exe"} <= set(p) for p in procs)