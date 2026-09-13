"""HIDS Agent — W2 Defense & Monitoring.

Host integrity monitoring:

  * baseline  — snapshot file hashes + metadata for the selected paths
                (writes a JSON baseline the user directs).
  * check     — compare current state against a baseline; report added,
                removed, and modified files.
  * processes — snapshot running processes (Linux /proc), read-only.

Read-oriented by default; the only writes are the baseline file you choose and
the default report output. Nothing is ever executed or altered.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="hids-agent",
    title="HIDS Agent (integrity + process monitor)",
    wave=2,
    description=(
        "Host integrity monitoring: take a file-hash baseline, later diff "
        "the live tree against it (added/removed/modified), and snapshot "
        "running processes. Read-only except for the baseline/report files "
        "you choose."
    ),
    category="defense",
    mode="read",
    privileges="none",
    fields=[
        FieldSpec(name="mode", label="Mode", type="combo", default="check",
                  options=["baseline", "check", "processes"],
                  help="baseline: capture state; check: diff against baseline; "
                       "processes: list running processes (Linux)"),
        FieldSpec(name="paths", label="Paths (comma-separated)", type="text",
                  default=".",
                  help="Directories/files to monitor (e.g. /etc,/usr/bin or .)"),
        FieldSpec(name="baseline", label="Baseline file", type="file", default="",
                  placeholder="(auto: <dir>/.hids-baseline.json)",
                  help="Baseline JSON path for baseline/check modes"),
        FieldSpec(name="exclusions", label="Exclusion globs", type="text", default="",
                  help="Comma-separated names/path substrings to skip"),
        FieldSpec(name="max_files", label="Max files", type="int", default=20000,
                  help="Hard limit on files scanned per run"),
    ],
)


def _iter_files(paths: List[Path], exclusions: List[str], limit: int):
    """Yield regular files under paths, skipping exclusions and symlinks."""
    count = 0
    for root in paths:
        root = Path(root).expanduser()
        if not root.exists():
            raise ValueError(f"path does not exist: {root}")
        if root.is_file():
            if count >= limit:
                return
            if not _excluded(str(root), exclusions):
                count += 1
                yield root, root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d for d in dirnames if not _excluded(str(Path(dirpath) / d), exclusions)]
            for name in filenames:
                if count >= limit:
                    return
                full = Path(dirpath) / name
                if _excluded(str(full), exclusions):
                    continue
                try:
                    if full.is_symlink():
                        continue
                    count += 1
                    yield full, full.relative_to(root)
                except OSError:
                    continue


def _excluded(path: str, exclusions: List[str]) -> bool:
    return any(ex in path for ex in exclusions if ex)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return ""  # unreadable file => empty hash (flag for review)
    return h.hexdigest()


def scan_state(paths: List[Path], exclusions: List[str], limit: int) -> Dict[str, dict]:
    """Return {relpath: {size, mtime, sha256}} for the monitored files."""
    state: Dict[str, dict] = {}
    for full, rel in _iter_files(paths, exclusions, limit):
        try:
            st = full.stat()
            state[str(rel)] = {
                "size": st.st_size,
                "mtime": round(st.st_mtime, 3),
                "sha256": _sha256_file(full),
            }
        except OSError:
            state[str(rel)] = {"size": 0, "mtime": 0, "sha256": ""}
    return state


def diff_states(baseline: Dict[str, dict], current: Dict[str, dict]) -> dict:
    added = sorted(set(current) - set(baseline))
    removed = sorted(set(baseline) - set(current))
    modified = []
    for path in sorted(set(baseline) & set(current)):
        prev, now = baseline[path], current[path]
        if prev.get("sha256") != now.get("sha256") or prev.get("size") != now.get("size"):
            modified.append({
                "path": path,
                "was": prev,
                "now": {k: now[k] for k in ("size", "mtime", "sha256")},
            })
    return {"added": added, "removed": removed, "modified": modified}


def process_snapshot() -> List[dict]:
    """Linux /proc process snapshot (read-only)."""
    processes = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            proc_dir = Path("/proc") / pid
            try:
                raw = (proc_dir / "stat").read_text()
                pid_s, _, rest = raw.partition(" ")
                if pid_s != pid:
                    continue
                lparen, rparen = rest.find("("), rest.rfind(")")
                if lparen < 0 or rparen < 0:
                    continue
                comm = rest[lparen + 1:rparen]
                tail = rest[rparen + 2:].split()
                if not tail:
                    continue
                state_code = tail[0]
                try:
                    with (proc_dir / "status").open() as fh:
                        status_lines = {}
                        for line in fh:
                            k, _, v = line.partition(":")
                            status_lines[k.strip()] = v.strip()
                    uid = status_lines.get("Uid", "?")
                    exe = ""
                    try:
                        exe = os.readlink(proc_dir / "exe")
                    except OSError:
                        exe = ""
                    processes.append({
                        "pid": int(pid),
                        "comm": comm,
                        "state": state_code,
                        "uid": uid,
                        "exe": exe,
                    })
                except OSError:
                    processes.append({"pid": int(pid), "comm": comm,
                                      "state": state_code, "uid": "?", "exe": ""})
            except (OSError, ValueError, IndexError):
                continue
    except OSError:
        raise ValueError("process snapshot requires Linux /proc")
    processes.sort(key=lambda p: p["pid"])
    return processes


def run(params: dict, ctx: ToolContext) -> dict:
    mode = params.get("mode", "check")
    paths_raw = str(params.get("paths") or ".").strip()
    paths = [Path(p.strip()) for p in paths_raw.split(",") if p.strip()]
    if not paths:
        raise ValueError("at least one path is required")
    exclusions = [e.strip() for e in str(params.get("exclusions") or "").split(",") if e.strip()]
    limit = int(params.get("max_files") or 20000)
    if limit < 1 or limit > 1_000_000:
        raise ValueError("max_files must be between 1 and 1,000,000")

    baseline_raw = str(params.get("baseline") or "").strip()
    baseline_path = Path(baseline_raw).expanduser() if baseline_raw else None

    if mode == "processes":
        procs = process_snapshot()
        return {
            "mode": "processes",
            "platform": "linux-proc",
            "process_count": len(procs),
            "processes": procs,
        }

    if mode == "baseline":
        if not baseline_path:
            baseline_path = ctx.output_dir / ".hids-baseline.json"
        ctx.ensure_output_dir()
        # never let the tool monitor its own output: exclude baseline + output dir
        self_exclusions = [str(baseline_path)]
        if ctx.output_dir.exists():
            self_exclusions.append(str(ctx.output_dir))
        state = scan_state(paths, exclusions + self_exclusions, limit)
        baseline = {
            "schema": 1,
            "algorithm": "sha256",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "paths": [str(p) for p in paths],
            "exclusions": exclusions,
            "files": state,
        }
        baseline_path.write_text(json.dumps(baseline, indent=1), encoding="utf-8")
        return {
            "mode": "baseline",
            "baseline_path": str(baseline_path),
            "files_recorded": len(state),
        }

    # check mode
    if not baseline_path:
        # look for the conventional name next to the first path
        default_candidate = paths[0] / ".hids-baseline.json" if paths[0].is_dir() \
            else paths[0].parent / ".hids-baseline.json"
        if default_candidate.exists():
            baseline_path = default_candidate
        else:
            raise ValueError(
                "check mode needs a baseline; run baseline mode first or pass "
                f"--baseline (looked for {default_candidate})")
    if not baseline_path.is_file():
        raise ValueError(f"baseline file not found: {baseline_path}")
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))

    self_path = str(baseline_path)
    current = scan_state(paths, exclusions + [self_path], limit)
    started = time.time()
    report = diff_states(baseline.get("files", {}), current)
    report["baseline_path"] = str(baseline_path)
    report["scanned_files"] = len(current)
    report["duration_ms"] = int((time.time() - started) * 1000)
    report["integrity"] = "CLEAN" if not (report["added"] or report["removed"]
                                          or report["modified"]) else "CHANGED"
    return report


def render(result: dict) -> str:
    if result.get("mode") == "baseline":
        return (f"Baseline written: {result['baseline_path']}\n"
                f"  files recorded: {result['files_recorded']}")
    if result.get("mode") == "processes":
        lines = [f"Process snapshot ({result['process_count']}):",
                 f"{'PID':<8}{'STATE':<7}{'UID':<12}{'COMM':<20}EXE"]
        for p in result["processes"]:
            lines.append(f"{p['pid']:<8}{p['state']:<7}{str(p['uid']):<12}"
                         f"{p['comm']:<20}{p['exe']}")
        return "\n".join(lines)

    lines = [
        f"Integrity check vs {result.get('baseline_path', '?')}  -> "
        f"{result.get('integrity', '?')}",
        f"scanned {result.get('scanned_files', 0)} files in "
        f"{result.get('duration_ms', 0)} ms",
    ]
    if result.get("added"):
        lines.append(f"\nADDED ({len(result['added'])}):")
        lines += [f"  + {p}" for p in result["added"][:40]]
    if result.get("removed"):
        lines.append(f"\nREMOVED ({len(result['removed'])}):")
        lines += [f"  - {p}" for p in result["removed"][:40]]
    if result.get("modified"):
        lines.append(f"\nMODIFIED ({len(result['modified'])}):")
        for m in result["modified"][:40]:
            lines.append(f"  ~ {m['path']}  (sha {m['now']['sha256'][:12]})")
    if not (result.get("added") or result.get("removed") or result.get("modified")):
        lines.append("\nNo changes detected.")
    return "\n".join(lines)