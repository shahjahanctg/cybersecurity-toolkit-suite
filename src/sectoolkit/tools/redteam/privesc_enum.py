"""Privilege Escalation Enum — W7 Red Team / C2.

Read-only local enumeration of common Linux privilege-escalation candidates:
SUID/SGID binaries, world-writable executables, writable cron/systemd/
autostart dirs, writable PATH components, uid-0 duplicates in /etc/passwd,
and the running kernel string (for CVE lookup). Prints guidance notes.

Windows note: run is best-effort where the tool detects Linux-only features;
the report includes a platform line.
"""

from __future__ import annotations

import datetime as _dt
import os
import platform
import pwd
import re
import stat
from pathlib import Path
from typing import Dict, List

from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="privesc-enum",
    title="Privilege Escalation Enum (Linux)",
    wave=7,
    description=(
        "Scan the local system for common privilege-escalation indicators: "
        "SUID/SGID files, world-writable executables, writable cron/systemd/"
        "autostart dirs, uid-0 duplicates, and kernel version. Read-only."
    ),
    category="redteam",
    mode="read",
    privileges="none",
    fields=[
        FieldSpec(name="scan_bins", label="Scan system binary dirs", type="bool",
                  default=True),
        FieldSpec(name="max_bins", label="Max SUID/writable results", type="int",
                  default=100),
        FieldSpec(name="output_dir", label="Output directory (JSON report)",
                  type="dir", default=None),
    ],
)

_BIN_DIRS = ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin",
             "/sbin", "/bin"]


def _scan_suid(bins: List[Path], max_bins: int) -> dict:
    suid, sgid, writable = [], [], []
    for d in bins:
        if not d.is_dir():
            continue
        try:
            for p in d.iterdir():
                if not p.is_file():
                    continue
                try:
                    st = p.stat()
                except OSError:
                    continue
                if stat.S_ISUID & st.st_mode:
                    suid.append(str(p))
                if stat.S_ISGID & st.st_mode:
                    sgid.append(str(p))
                if st.st_mode & 0o0002:
                    writable.append(str(p))
                if len(suid) + len(sgid) >= max_bins:
                    break
        except PermissionError:
            continue
    return {"suid": suid[:max_bins], "sgid": sgid[:max_bins],
            "writable": writable[:max_bins]}


def _writable_dirs() -> List[str]:
    checks = ["/etc", "/etc/cron.d", "/etc/cron.daily", "/etc/crontab",
              "/etc/systemd/system", "/etc/init.d", "/etc/rc.d"]
    out = []
    for name in checks:
        p = Path(name)
        if p.exists():
            try:
                st = p.stat()
                if st.st_mode & 0o0002:
                    out.append(name)
                elif p.is_file() and (p.parent.stat().st_mode & 0o0002):
                    out.append(name + " (writable parent)")
            except OSError:
                continue
    for base in ("/etc/cron.d", "/etc/e2cron.d"):
        p = Path(base)
        if p.is_dir():
            try:
                for f in p.iterdir():
                    if f.is_file() and (f.stat().st_mode & 0o0002):
                        out.append(str(f))
            except OSError:
                continue
    return out


def _passwd_uid0() -> List[dict]:
    out = []
    try:
        with open("/etc/passwd", "r", encoding="utf-8") as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    parts = line.split(":")
                    if len(parts) >= 4 and parts[2] == "0" and parts[3] == "0":
                        out.append({"user": parts[0], "shell": parts[-1].strip()})
    except OSError:
        pass
    return out


def _writable_path_dirs() -> List[str]:
    out = []
    path = os.environ.get("PATH", "")
    for d in path.split(":"):
        if not d:
            continue
        try:
            if Path(d).stat().st_mode & 0o0002:
                out.append(d)
        except OSError:
            continue
    return out


def _kernel_info() -> str:
    return platform.release() or platform.version() or "unknown"


def run(params: dict, ctx: ToolContext) -> dict:
    scan_bins = bool(params.get("scan_bins", True))
    try:
        max_bins = int(params.get("max_bins") or 100)
    except (TypeError, ValueError):
        raise ValueError("max_bins must be an integer")

    findings: List[dict] = []
    if platform.system().lower() == "linux":
        if scan_bins:
            result = _scan_suid([Path(d) for d in _BIN_DIRS], max_bins)
            for k, label in (("suid", "SUID binary"), ("sgid", "SGID binary"),
                             ("writable", "world-writable executable")):
                for path in result[k]:
                    findings.append({"kind": label, "path": path, "detail": ""})
        for d in _writable_dirs():
            findings.append({"kind": "writable-dir", "path": d, "detail": ""})
        for p in _writable_path_dirs():
            findings.append({"kind": "writable-PATH", "path": p,
                             "detail": "PATH component writable — "
                                       "check for binary hijacking"})
        for u in _passwd_uid0():
            findings.append({"kind": "uid0-user", "path": "/etc/passwd",
                             "detail": f"{u['user']} uid=0 shell={u['shell']}"})
        kernel = _kernel_info()
        findings.append({"kind": "kernel", "path": "",
                         "detail": f"kernel {kernel} — compare against "
                                   f"known local privesc CVEs"})
    else:
        findings.append({
            "kind": "platform", "path": "",
            "detail": f"running on {platform.system()} — "
                      f"Linux-only checks skipped; inspect manually"})

    report = {
        "os": platform.system().lower(),
        "platform_line": platform.platform(),
        "findings_count": len(findings),
        "findings": findings,
        "finished_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }
    written = ""
    out_dir = params.get("output_dir")
    if out_dir:
        import json as _json
        target = Path(str(out_dir)) / "privesc-report.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(_json.dumps(report, indent=2), encoding="utf-8")
        written = str(target)
    report["output_file"] = written
    return report


def render(result: dict) -> str:
    lines = [f"Privesc enum on {result['platform_line']}: "
             f"{result['findings_count']} findings"]
    for f in result["findings"]:
        pathpart = f" {f['path']}" if f["path"] else ""
        detail = f" — {f['detail']}" if f["detail"] else ""
        lines.append(f"  [{f['kind']}]{pathpart}{detail}")
    if result.get("output_file"):
        lines.append(f"Report saved to {result['output_file']}")
    return "\n".join(lines)