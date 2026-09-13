"""Memory Forensics — W5 Forensics.

Two modes:
- ``vol``: run a Volatility 3 plugin against a memory dump and parse its
  JSON/CSV output (requires the ``vol`` binary).
- ``strings``: pure-Python extraction of printable ASCII/UTF-8 strings from
  the dump (no external tools), for quick triage of processes/paths/URLs.

Read-only. Works on local dumps you are authorized to analyze.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import List

from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="memory-forensics",
    title="Memory Forensics (Volatility 3 wrapper + strings)",
    wave=5,
    description=(
        "Analyze a RAM dump: run a Volatility 3 plugin (e.g. "
        "windows.pslist.PsList) and parse JSON/CSV output, and/or extract "
        "printable strings for quick triage. Read-only."
    ),
    category="forensics",
    mode="read",
    privileges="none",
    fields=[
        FieldSpec(name="image", label="Memory dump (raw)", type="file",
                  required=True),
        FieldSpec(name="mode", label="Mode", type="combo",
                  options=["vol", "strings"], default="strings"),
        FieldSpec(name="plugin", label="Volatility plugin", type="text",
                  default="windows.pslist.PsList",
                  help="e.g. windows.pslist.PsList, linux.pslist..."),
        FieldSpec(name="vol_binary", label="Volatility binary", type="text",
                  default="vol"),
        FieldSpec(name="output_dir", label="Output directory", type="dir",
                  default=None,
                  help="writes plugin report / strings.txt"),
        FieldSpec(name="min_string_len", label="Min string length", type="int",
                  default=6),
        FieldSpec(name="top_strings", label="Max strings to report", type="int",
                  default=50),
    ],
)

_STRING_RE = re.compile(rb"[\x20-\x7e\xc0-\xff]{6,}")


def _extract_strings(data: bytes, min_len: int, top: int) -> List[str]:
    out: List[str] = []
    for m in _STRING_RE.finditer(data):
        raw = m.group()
        if len(raw) < min_len:
            continue
        try:
            s = raw.decode("utf-8", "replace").strip()
        except Exception:
            continue
        if s and s.isprintable():
            out.append(s)
    return out[:top]


def _run_vol(binary: str, image: Path, plugin: str) -> str:
    import shutil
    if shutil.which(binary) is None:
        raise RuntimeError(
            f"volatility binary {binary!r} not found on PATH. Install "
            "volatility3 (pip install volatility3) and pass --vol-binary, "
            "or use mode=strings.")
    cmd = [binary, "-f", str(image), "-r", "json", plugin]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if proc.returncode != 0:
        raise RuntimeError(f"vol exited {proc.returncode}: {proc.stderr[:500]}")
    if not proc.stdout.strip():
        raise RuntimeError("vol produced no output")
    return proc.stdout


def run(params: dict, ctx: ToolContext) -> dict:
    raw = params.get("image")
    if not raw:
        raise ValueError("image is required")
    image = Path(str(raw)) if not isinstance(raw, Path) else raw
    if not image.exists():
        raise ValueError(f"image does not exist: {image}")
    mode = str(params.get("mode") or "strings")
    if mode not in ("vol", "strings"):
        raise ValueError("mode must be vol or strings")
    out_dir = params.get("output_dir")
    if out_dir:
        out_dir = Path(str(out_dir))
        out_dir.mkdir(parents=True, exist_ok=True)

    data = image.read_bytes()

    if mode == "strings":
        min_len = int(params.get("min_string_len") or 6)
        top = int(params.get("top_strings") or 50)
        strings = _extract_strings(data, min_len, top)
        written = ""
        if out_dir:
            target = out_dir / (image.name + ".strings.txt")
            target.write_text("\n".join(strings) + "\n", encoding="utf-8",
                              errors="replace")
            written = str(target)
        return {
            "mode": "strings",
            "image": str(image),
            "extracted": len(strings),
            "strings": strings,
            "output_file": written,
        }

    plugin = str(params.get("plugin") or "windows.pslist.PsList")
    vol_binary = str(params.get("vol_binary") or "vol")
    report = _run_vol(vol_binary, image, plugin)
    import json as _json
    parsed = None
    try:
        parsed = _json.loads(report)
    except _json.JSONDecodeError:
        parsed = None
    written = ""
    if out_dir:
        target = out_dir / (image.name + f".{plugin}.json")
        target.write_text(report, encoding="utf-8", errors="replace")
        written = str(target)
    count = len(parsed) if isinstance(parsed, list) else (1 if parsed else 0)
    return {
        "mode": "vol",
        "image": str(image),
        "plugin": plugin,
        "records": count,
        "output_file": written,
        "report": report[:100000],
    }


def render(result: dict) -> str:
    if result["mode"] == "strings":
        lines = [f"Strings from {result['image']}: {result['extracted']} shown"]
        for i, s in enumerate(result["strings"], 1):
            lines.append(f"  {i:>3} {s[:90]}")
        if result.get("output_file"):
            lines.append(f"Saved to {result['output_file']}")
        return "\n".join(lines)
    lines = [f"Volatility plugin {result['plugin']}: "
             f"{result['records']} records"]
    if result.get("output_file"):
        lines.append(f"Report saved to {result['output_file']}")
    return "\n".join(lines)