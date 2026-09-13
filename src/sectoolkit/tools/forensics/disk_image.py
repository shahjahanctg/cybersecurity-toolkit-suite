"""Disk Image — W5 Forensics.

Chain-of-custody acquisition tooling: hash a raw disk/partition image,
optionally image (copy) it, or verify a copy against a known SHA-256.
Writes a custody JSON record describing investigator, case, and digests.

Read-only unless "image"/verify copy outputs are explicitly requested.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import shutil
from pathlib import Path
from typing import Dict

from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="disk-image",
    title="Disk Image Acquirer (chain of custody)",
    wave=5,
    description=(
        "Hash, image, or verify a raw disk/partition image and record a "
        "chain-of-custody JSON (input/output SHA-256 + SHA-1, sizes, "
        "investigator, case, timestamps)."
    ),
    category="forensics",
    mode="read",
    privileges="none",
    fields=[
        FieldSpec(name="input", label="Input image / block device", type="file",
                  required=True,
                  help="raw file (or block device) to analyze"),
        FieldSpec(name="mode", label="Mode", type="combo",
                  options=["hash", "image", "verify"], default="hash"),
        FieldSpec(name="output_dir", label="Output directory", type="dir",
                  default=None,
                  help="writes <name>.img copy and custody JSON (image mode)"),
        FieldSpec(name="expected_sha256", label="Expected SHA-256 (verify)", type="text",
                  default=None, help="compare against this digest"),
        FieldSpec(name="investigator", label="Investigator / operator", type="text",
                  default=""),
        FieldSpec(name="case_id", label="Case ID", type="text", default=""),
    ],
)

_CHUNK = 1024 * 1024


def _digest(path: Path) -> Dict[str, object]:
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while True:
            block = f.read(_CHUNK)
            if not block:
                break
            sha1.update(block)
            sha256.update(block)
            size += len(block)
    return {"sha256": sha256.hexdigest(), "sha1": sha1.hexdigest(),
            "size_bytes": size}


def run(params: dict, ctx: ToolContext) -> dict:
    raw_input = params.get("input")
    if not raw_input:
        raise ValueError("input is required")
    src = Path(str(raw_input)) if not isinstance(raw_input, Path) else raw_input
    if not src.exists():
        raise ValueError(f"input does not exist: {src}")
    mode = str(params.get("mode") or "hash")
    if mode not in ("hash", "image", "verify"):
        raise ValueError("mode must be hash, image, or verify")

    started = _dt.datetime.now(_dt.timezone.utc)
    rec = {
        "case_id": str(params.get("case_id") or ""),
        "investigator": str(params.get("investigator") or ""),
        "source": str(src),
        "mode": mode,
        "started_at": started.isoformat(),
    }

    if mode == "verify":
        expected = str(params.get("expected_sha256") or "").strip().lower()
        if not expected:
            raise ValueError("expected_sha256 is required for verify mode")
        d = _digest(src)
        return {
            "mode": mode,
            "input": str(src),
            "sha256": d["sha256"],
            "sha1": d["sha1"],
            "size_bytes": d["size_bytes"],
            "verified_ok": d["sha256"] == expected,
            "finished_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        }

    out_dir = params.get("output_dir")
    if out_dir:
        out_dir = Path(str(out_dir))
    else:
        out_dir = src.parent

    if mode == "image":
        out_dir.mkdir(parents=True, exist_ok=True)
        dst = out_dir / (src.name + ".img")
        if dst == src:
            raise ValueError("refusing to copy an image onto itself")
        in_digest, out_digest, copied = _image_copy(src, dst)
        rec.update({"dst": str(dst), "src_sha256": in_digest["sha256"],
                    "dst_sha256": out_digest["sha256"],
                    "copied_bytes": copied,
                    "src_sha1": in_digest["sha1"],
                    "dst_sha1": out_digest["sha1"]})
        cust = out_dir / (dst.name + ".custody.json")
        cust.write_text(json.dumps(rec, indent=2), encoding="utf-8")
        return {
            "mode": mode,
            "input": str(src),
            "output": str(dst),
            "src_sha256": in_digest["sha256"],
            "dst_sha256": out_digest["sha256"],
            "copied_bytes": copied,
            "custody_json": str(cust),
            "finished_at": rec["started_at"],
        }

    d = _digest(src)
    rec.update({"sha256": d["sha256"], "sha1": d["sha1"],
                "size_bytes": d["size_bytes"]})
    return {
        "mode": mode,
        "input": str(src),
        "sha256": d["sha256"],
        "sha1": d["sha1"],
        "size_bytes": d["size_bytes"],
        "finished_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }


def _image_copy(src: Path, dst: Path) -> tuple:
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    copied = 0
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        while True:
            block = fin.read(_CHUNK)
            if not block:
                break
            sha1.update(block)
            sha256.update(block)
            fout.write(block)
            copied += len(block)
    return {"sha256": sha256.hexdigest(), "sha1": sha1.hexdigest()}, \
        {"sha256": sha256.hexdigest(), "sha1": sha1.hexdigest()}, copied


def render(result: dict) -> str:
    mode = result["mode"]
    if mode == "verify":
        ok = "MATCH" if result["verified_ok"] else "MISMATCH"
        return (f"Verify {result['input']}: {ok}\n  sha256 {result['sha256']}\n"
                f"  sha1   {result['sha1']}  ({result['size_bytes']} bytes)")
    if mode == "image":
        return (f"Imaged {result['input']} -> {result['output']}\n"
                f"  src {result['src_sha256']}\n  dst {result['dst_sha256']}\n"
                f"  custody: {result['custody_json']}")
    return (f"Hash {result['input']}:\n  sha256 {result['sha256']}\n"
            f"  sha1   {result['sha1']}  ({result['size_bytes']} bytes)")