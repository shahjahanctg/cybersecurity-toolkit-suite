"""Resolve bundled data files shipped inside the package."""

from __future__ import annotations

from pathlib import Path

_DATA = Path(__file__).resolve().parents[1] / "data"


def data_file(name: str) -> Path:
    """Absolute path of a bundled data file (data/* under the package)."""
    return _DATA / name


def read_lines(name: str) -> list:
    """Read a line-based bundled data file, skipping blanks and comments."""
    out = []
    for raw in data_file(name).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out