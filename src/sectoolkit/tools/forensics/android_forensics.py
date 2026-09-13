"""Android Forensics — W5 Forensics.

Parses an adb Android backup archive (``.ab``, versions 1/2, unencrypted):
read the header, decompress the deflate payload when flagged, and either
list the contained tar entries or extract them to an output directory.

Unencrypted backups only (encryption is refused with a clear error — the
material belongs to the data owner). Read-only against the backup file.
"""

from __future__ import annotations

import datetime as _dt
import io
import tarfile
import zlib
from pathlib import Path
from typing import List

from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="android-forensics",
    title="Android Forensics (adb backup .ab parser)",
    wave=5,
    description=(
        "Parse an unencrypted adb backup (.ab) archive: validate the header, "
        "decompress the tar payload, list entries or extract them to an "
        "output directory."
    ),
    category="forensics",
    mode="read",
    privileges="none",
    fields=[
        FieldSpec(name="backup", label="Android backup (.ab) file", type="file",
                  required=True),
        FieldSpec(name="mode", label="Mode", type="combo",
                  options=["list", "extract"], default="list"),
        FieldSpec(name="output_dir", label="Extract to directory", type="dir",
                  default=None,
                  help="required for extract mode"),
        FieldSpec(name="max_entries", label="Max entries to list", type="int",
                  default=500),
    ],
)

_MAGIC = b"ANDROID BACKUP\n"


def _read_backup(path: Path) -> tuple:
    """Read .ab header; return (version, flags, compression, enc, payload_bytes)."""
    with open(path, "rb") as f:
        magic = f.readline()
        if magic != _MAGIC:
            raise ValueError("not an Android backup file (bad magic)")
        version = f.readline().strip()
        flags = f.readline().strip()
        compression = f.readline().strip()
        enc = f.readline().strip()
        payload_start = f.tell()
        payload = f.read()
    try:
        version_i = int(version)
        compression_i = int(compression)
    except ValueError as exc:
        raise ValueError("malformed Android backup header") from exc
    if version_i not in (1, 2):
        raise ValueError(f"unsupported backup version {version_i}")
    if enc != b"(none)":
        raise ValueError(
            "encrypted Android backup refused: backups of app data belong to "
            "the data owner; re-run adb backup without a password.")
    if compression_i == 1:
        payload = zlib.decompress(payload)
    return version_i, int(flags), compression_i, enc, payload


def _parse_backup(path: Path, max_entries: int) -> dict:
    version, flags, compression, enc, payload = _read_backup(path)
    entries: List[dict] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(payload)) as tar:
            for i, member in enumerate(tar.getmembers()):
                if i >= max_entries:
                    break
                entries.append({
                    "path": member.name,
                    "type": member.type,
                    "size": member.size,
                    "mtime": member.mtime,
                })
    except tarfile.TarError as exc:
        raise ValueError(f"payload is not a valid archive: {exc}") from exc

    return {"version": version, "compressed": compression == 1,
            "entries": entries, "entry_count": len(entries)}


def _extract(path: Path, out_dir: Path) -> List[str]:
    _, _, _, _, payload = _read_backup(path)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: List[str] = []
    with tarfile.open(fileobj=io.BytesIO(payload)) as tar:
        for member in tar.getmembers():
            safe = Path(member.name).name  # keep basename only, avoid traversal
            if not safe or safe in (".", ".."):
                continue
            extracted = tar.extractfile(member)
            target = out_dir / safe
            if extracted is None:
                continue
            with open(target, "wb") as f:
                while True:
                    chunk = extracted.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
            written.append(str(target))
    return written


def run(params: dict, ctx: ToolContext) -> dict:
    raw = params.get("backup")
    if not raw:
        raise ValueError("backup is required")
    backup = Path(str(raw)) if not isinstance(raw, Path) else raw
    if not backup.exists():
        raise ValueError(f"backup does not exist: {backup}")
    mode = str(params.get("mode") or "list")
    if mode not in ("list", "extract"):
        raise ValueError("mode must be list or extract")
    try:
        max_entries = int(params.get("max_entries") or 500)
    except (TypeError, ValueError):
        raise ValueError("max_entries must be an integer")

    info = _parse_backup(backup, max_entries)
    written: List[str] = []
    if mode == "extract":
        out = params.get("output_dir")
        if not out:
            raise ValueError("output_dir is required for extract mode")
        written = _extract(backup, Path(str(out)))

    return {
        "backup": str(backup),
        "version": info["version"],
        "compressed": info["compressed"],
        "entry_count": info["entry_count"],
        "entries": info["entries"],
        "extracted_files": written,
        "finished_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }


def render(result: dict) -> str:
    lines = [f"Android backup {result['backup']} (v{result['version']}, "
             f"{'compressed' if result['compressed'] else 'raw'}, "
             f"{result['entry_count']} entries)"]
    for e in result["entries"]:
        lines.append(f"  {e['path']:<55} {e['size']:>10}  {e['type']}")
    for f in result.get("extracted_files", []):
        lines.append(f"  extracted -> {f}")
    return "\n".join(lines)