"""Deleted File Recovery — W5 Forensics.

Signature-based carving of common file types from a raw disk/partition
image or leftover slack. Runs entirely in-memory on the bytes you give it,
deduplicates recovered artifacts by content hash, and writes them under a
timestamped folder in the output directory.

Pure read against the source; writes only to the requested output dir.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
from pathlib import Path
from typing import List

from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="deleted-recovery",
    title="Deleted File Recovery (signature carving)",
    wave=5,
    description=(
        "Carve PNG/JPG/PDF/ZIP/ELF/GIF/gzip artifacts out of a raw image "
        "using signature + header analysis. Dedupes by content hash and "
        "writes recovered files to the chosen output directory."
    ),
    category="forensics",
    mode="read",
    privileges="none",
    fields=[
        FieldSpec(name="image", label="Raw image to carve", type="file",
                  required=True),
        FieldSpec(name="output_dir", label="Output directory", type="dir",
                  required=True),
        FieldSpec(name="min_size", label="Min carved size (bytes)", type="int",
                  default=512),
        FieldSpec(name="max_size", label="Max carved size (bytes)", type="int",
                  default=50 * 1024 * 1024),
    ],
)

_SIGNATURES = [
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("jpg", b"\xff\xd8\xff"),
    ("pdf", b"%PDF-"),
    ("zip", b"PK\x03\x04"),
    ("gif", b"GIF87a"),
    ("gzip", b"\x1f\x8b\x08"),
    ("elf", b"\x7fELF"),
    ("docx", b"PK\x03\x04"),
]


def _carve(data: bytes, min_size: int, max_size: int) -> List[dict]:
    hits: List[dict] = []
    seen: set = set()
    for kind, sig in _SIGNATURES:
        if not sig:
            continue
        offsets: List[int] = []
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx < 0:
                break
            offsets.append(idx)
            start = idx + len(sig)
        for n, off in enumerate(offsets):
            nxt = offsets[n + 1] if n + 1 < len(offsets) else len(data)
            length = min(nxt - off, max_size)
            if length < min_size:
                continue
            payload = data[off:off + length]
            digest = hashlib.sha256(payload).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            hits.append({
                "kind": kind,
                "offset": off,
                "size": length,
                "sha256": digest,
            })
    return hits


def run(params: dict, ctx: ToolContext) -> dict:
    raw = params.get("image")
    if not raw:
        raise ValueError("image is required")
    image = Path(str(raw)) if not isinstance(raw, Path) else raw
    if not image.exists():
        raise ValueError(f"image does not exist: {image}")
    out = params.get("output_dir")
    if not out:
        raise ValueError("output_dir is required")
    out_dir = Path(str(out))
    try:
        min_size = int(params.get("min_size") or 512)
        max_size = int(params.get("max_size") or 50 * 1024 * 1024)
    except (TypeError, ValueError):
        raise ValueError("min_size/max_size must be integers")
    if min_size < 1 or max_size < 1 or max_size < min_size:
        raise ValueError("max_size must be >= min_size >= 1")

    data = image.read_bytes()
    hits = _carve(data, min_size, max_size)

    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = out_dir / "recovered"
    written: List[str] = []
    for i, h in enumerate(hits, 1):
        payload = data[h["offset"]:h["offset"] + h["size"]]
        name = f"{h['kind']}_at_{h['offset']}_{h['sha256'][:8]}.bin"
        target = dest / name
        target.parent.mkdir(parents=True, exist_ok=True)
        extname = f"{i:03d}_{h['kind']}_{h['sha256'][:8]}.bin"
        target = dest / extname
        target.write_bytes(payload)
        written.append(str(target))

    return {
        "image": str(image),
        "signatures_tried": len(_SIGNATURES),
        "carved_count": len(hits),
        "recovered": hits,
        "output_dir": str(dest),
        "written_files": written,
        "run_id": stamp,
    }


def render(result: dict) -> str:
    lines = [f"Carved {result['carved_count']} artifacts from "
             f"{result['image']} -> {result['output_dir']}"]
    for i, h in enumerate(result["recovered"], 1):
        lines.append(
            f"  {i:>3} {h['kind']:<6} @{h['offset']:<10} "
            f"{h['size']} bytes  {h['sha256'][:12]}…")
    return "\n".join(lines)