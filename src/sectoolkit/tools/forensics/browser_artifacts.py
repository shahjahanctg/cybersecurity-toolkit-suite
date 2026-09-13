"""Browser Artifacts — W5 Forensics.

Reads browser history/cookies from a Firefox or Chrome profile directory and
prints (optionally dumps to JSON) the recent records: URLs, visits, cookies.

Firefox is preferred and fully supported (sqlite3). Chrome keeps its
databases locked while the browser runs; this tool opens them read-only and
will report whichever of History/Cookies/Login Data are readable.

Read-only: never modifies the profile.
"""

from __future__ import annotations

import datetime as _dt
import json
import sqlite3
from pathlib import Path
from typing import Dict, List

from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="browser-artifacts",
    title="Browser Artifacts (Firefox/Chrome history + cookies)",
    wave=5,
    description=(
        "Extract recent URLs, visits, and cookies from a Firefox or Chrome "
        "profile directory (sqlite). Optionally dump the result to a JSON "
        "report file. Read-only against the profile."
    ),
    category="forensics",
    mode="read",
    privileges="none",
    fields=[
        FieldSpec(name="profile_dir", label="Browser profile directory",
                  type="dir", required=True),
        FieldSpec(name="browser", label="Browser", type="combo",
                  options=["auto", "firefox", "chrome"], default="auto"),
        FieldSpec(name="output_file", label="Output JSON report (optional)",
                  type="file", default=None),
        FieldSpec(name="max_rows", label="Max rows per table", type="int",
                  default=200),
    ],
)


def _detect(profile: Path) -> str:
    if (profile / "places.sqlite").exists():
        return "firefox"
    if (profile / "History").exists():
        return "chrome"
    raise ValueError(
        "cannot detect browser: profile has neither places.sqlite (Firefox) "
        "nor History (Chrome)")


def _read_firefox(profile: Path, max_rows: int) -> List[dict]:
    rows: List[dict] = []
    hist = profile / "places.sqlite"
    if hist.exists():
        con = sqlite3.connect(f"file:{hist}?mode=ro", uri=True)
        try:
            cur = con.execute(
                "SELECT url, title, visit_count, last_visit_date "
                "FROM moz_places ORDER BY last_visit_date DESC LIMIT ?",
                (max_rows,))
            for url, title, vc, last in cur:
                if last is None:
                    t = None
                else:
                    t = _dt.datetime.fromtimestamp(
                        last / 1_000_000, tz=_dt.timezone.utc).isoformat()
                rows.append({"kind": "url", "url": url, "title": title,
                             "visit_count": vc, "last_visit": t})
        finally:
            con.close()
    cks = profile / "cookies.sqlite"
    if cks.exists():
        con = sqlite3.connect(f"file:{cks}?mode=ro", uri=True)
        try:
            cur = con.execute(
                "SELECT name, host, path, value, creationTime, expiry "
                "FROM moz_cookies ORDER BY creationTime DESC LIMIT ?",
                (max_rows,))
            for name, host, path, value, created, expiry in cur:
                rows.append({"kind": "cookie", "name": name, "host": host,
                             "path": path, "value": value,
                             "created": created, "expiry": expiry})
        finally:
            con.close()
    return rows


def _read_chrome(profile: Path, max_rows: int) -> List[dict]:
    rows: List[dict] = []
    hist = profile / "History"
    if hist.exists():
        try:
            con = sqlite3.connect(f"file:{hist}?mode=ro", uri=True)
            try:
                cur = con.execute(
                    "SELECT url, title, visit_count, last_visit_time "
                    "FROM urls ORDER BY last_visit_time DESC LIMIT ?",
                    (max_rows,))
                for url, title, vc, last in cur:
                    if last is None:
                        t = None
                    else:
                        t = _dt.datetime.fromtimestamp(
                            last / 1_000_000 - 11644473600,
                            tz=_dt.timezone.utc).isoformat()
                    rows.append({"kind": "url", "url": url, "title": title,
                                 "visit_count": vc, "last_visit": t})
            finally:
                con.close()
        except sqlite3.DatabaseError:
            rows.append({"kind": "error",
                         "detail": "History locked/unreadable — "
                                   "close Chrome and retry"})
    cks = profile / "Cookies"
    if cks.exists():
        try:
            con = sqlite3.connect(f"file:{cks}?mode=ro", uri=True)
            try:
                cur = con.execute(
                    "SELECT host_key, name, path, encrypted_value "
                    "FROM cookies LIMIT ?", (max_rows,))
                for host, name, path, _val in cur:
                    rows.append({"kind": "cookie", "host": host, "name": name,
                                 "path": path,
                                 "value": "<encrypted>"})
            finally:
                con.close()
        except sqlite3.DatabaseError:
            rows.append({"kind": "error",
                         "detail": "Cookies locked/unreadable — "
                                   "close Chrome and retry"})
    return rows


def run(params: dict, ctx: ToolContext) -> dict:
    raw = params.get("profile_dir")
    if not raw:
        raise ValueError("profile_dir is required")
    profile = Path(str(raw)) if not isinstance(raw, Path) else raw
    if not profile.is_dir():
        raise ValueError(f"profile directory not found: {profile}")
    browser = str(params.get("browser") or "auto")
    if browser == "auto":
        browser = _detect(profile)
    if browser not in ("firefox", "chrome"):
        raise ValueError("browser must be auto, firefox, or chrome")

    try:
        max_rows = int(params.get("max_rows") or 200)
    except (TypeError, ValueError):
        raise ValueError("max_rows must be an integer")
    if max_rows < 1:
        raise ValueError("max_rows must be >= 1")

    rows = (_read_firefox(profile, max_rows) if browser == "firefox"
            else _read_chrome(profile, max_rows))

    report = {"browser": browser, "profile": str(profile), "rows": rows,
              "count": len(rows),
              "extracted_at": _dt.datetime.now(_dt.timezone.utc).isoformat()}

    written = ""
    out_file = params.get("output_file")
    if out_file:
        target = Path(str(out_file))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, indent=2), encoding="utf-8")
        written = str(target)

    return {**report, "output_file": written}


def render(result: dict) -> str:
    lines = [f"{result['browser']} artifacts from {result['profile']}: "
             f"{result['count']} records"]
    for r in result["rows"]:
        if r["kind"] == "error":
            lines.append(f"  !! {r['detail']}")
        elif r["kind"] == "cookie":
            lines.append(f"  cookie  {r['host']}{r.get('path', '')}"
                         f"  {r['name']}")
        else:
            lines.append(f"  url     {r['url']}" +
                         (f"  ({r['title'] or ''})"[:70] if r.get('title') else ""))
    if result.get("output_file"):
        lines.append(f"Report saved to {result['output_file']}")
    return "\n".join(lines)