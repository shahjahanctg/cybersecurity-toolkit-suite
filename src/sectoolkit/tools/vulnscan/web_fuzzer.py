"""Web App Fuzzer — W4 Vuln Scanning.

Wordlist-driven discovery of paths on a web target. Uses a bundled
starter path list or any wordlist file. Interesting (non-filtered) responses
are reported with status and size. Threaded with a live result cap.
"""

from __future__ import annotations

import concurrent.futures as futures
import socket
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="web-fuzzer",
    title="Web App Fuzzer (path discovery)",
    wave=4,
    description=(
        "Wordlist-driven path discovery against a web app. Flags every response "
        "whose status is not in the filter list."
    ),
    category="vulnscan",
    mode="act",
    privileges="none",
    target_fields=["target_url"],
    fields=[
        FieldSpec(name="target_url", label="Base URL", type="text",
                  required=True, placeholder="http://127.0.0.1:8080/"),
        FieldSpec(name="wordlist", label="Wordlist file", type="file",
                  default=None, help="one path per line; bundled list if empty"),
        FieldSpec(name="method", label="Method", type="combo",
                  options=["GET", "POST"], default="GET"),
        FieldSpec(name="threads", label="Threads", type="int", default=10),
        FieldSpec(name="filter_status", label="Filter statuses", type="text",
                  default="404",
                  help="comma-separated statuses treated as not-found"),
        FieldSpec(name="timeout", label="Request timeout (s)", type="int", default=5),
        FieldSpec(name="max_results", label="Max reported hits", type="int",
                  default=200),
    ],
)

_DEFAULT_PATHS = [
    "admin/", "admin.php", "api/", "api/v1/", "backup/", "backup.zip",
    "config", "config.php", "config.json", "db.sql", "debug", "docs/",
    "env", "favicon.ico", "health", "index.php", "install/", "login",
    "login.php", "logs/", "manage/", "panel/", "phpinfo.php", "private/",
    "robots.txt", "secret/", "server-status", "settings", "sitemap.xml",
    "status", "swagger.json", "test.php", "tmp/", "uploads/", "user",
    "users", "vendor/", ".git/config", ".env", "wp-admin/", "wp-login.php",
]


def _load_wordlist(path) -> list:
    if path:
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    else:
        lines = _DEFAULT_PATHS
    out = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            out.append(stripped)
    if not out:
        raise ValueError("empty wordlist")
    return out


def _check_target_url(url: str, ctx: ToolContext) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("target_url must be http(s)://...")
    return parsed.hostname or ""


def _fetch_one(base: str, path: str, method: str, timeout: float,
               user_agent: str) -> dict:
    url = base.rstrip("/") + "/" + path.lstrip("/")
    req = Request(url, method=method, headers={"User-Agent": user_agent})
    start = time.monotonic()
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read(512)
            return {"url": url, "status": resp.status,
                    "length": int(resp.headers.get("Content-Length", len(body)) or
                                  len(body)),
                    "location": resp.headers.get("Location", ""),
                    "elapsed_ms": int((time.monotonic() - start) * 1000)}
    except HTTPError as exc:
        try:
            body = exc.read(256)
        except OSError:
            body = b""
        return {"url": url, "status": exc.code,
                "length": len(body), "location": exc.headers.get("Location", ""),
                "elapsed_ms": int((time.monotonic() - start) * 1000)}
    except (URLError, OSError) as exc:
        return {"url": url, "status": 0, "length": 0,
                "error": str(getattr(exc, "reason", exc)),
                "elapsed_ms": int((time.monotonic() - start) * 1000)}


def run(params: dict, ctx: ToolContext) -> dict:
    url = str(params.get("target_url") or "").strip()
    if not url:
        raise ValueError("target_url is required")
    _check_target_url(url, ctx)
    wordlist = _load_wordlist(params.get("wordlist"))
    method = str(params.get("method") or "GET").upper()
    if method not in ("GET", "POST"):
        raise ValueError("method must be GET or POST")
    try:
        threads = int(params.get("threads") or 10)
        timeout = float(params.get("timeout") or 5)
        max_results = int(params.get("max_results") or 200)
    except (TypeError, ValueError):
        raise ValueError("threads/timeout/max_results must be numbers")
    if threads < 1 or threads > 64:
        raise ValueError("threads must be in [1, 64]")
    if max_results < 1:
        raise ValueError("max_results must be >= 1")
    filter_status = {int(s) for s in
                     str(params.get("filter_status") or "404").split(",") if s.strip()}

    ua = ctx.config.get("user_agent", "SecurityToolkitSuite/0.1.0")
    results: list = []
    errors = 0
    stop = ctx.extra.get("stop_event")
    start = datetime.now(timezone.utc)
    clock = time.monotonic()

    def worker(path: str) -> dict:
        if stop is not None and stop.is_set():
            return None
        return _fetch_one(url, path, method, timeout, ua)

    def should_report(res: dict) -> bool:
        return res["status"] != 0 and res["status"] not in filter_status

    try:
        with futures.ThreadPoolExecutor(max_workers=threads) as ex:
            for res in ex.map(worker, wordlist):
                if res is None:
                    continue
                if res["status"] == 0:
                    errors += 1
                    continue
                if should_report(res):
                    results.append(res)
                    if len(results) >= max_results:
                        ex.shutdown(wait=False, cancel_futures=True)
                        break
    finally:
        pass

    results.sort(key=lambda r: (r["status"], r["url"]))
    duration = round(time.monotonic() - clock, 2)
    counts: dict = {}
    for r in results:
        counts[str(r["status"])] = counts.get(str(r["status"]), 0) + 1
    return {
        "base_url": url,
        "paths_tested": len(wordlist),
        "hits": len(results),
        "errors": errors,
        "duration_s": duration,
        "status_counts": counts,
        "results": results[:max_results],
        "finished_at": start.isoformat(),
    }


def render(result: dict) -> str:
    lines = [
        f"Fuzzed {result['base_url']}: {result['paths_tested']} paths, "
        f"{result['hits']} hits in {result['duration_s']}s",
    ]
    if result.get("status_counts"):
        lines.append("  statuses: " + ", ".join(
            f"{k}={v}" for k, v in sorted(result["status_counts"].items())))
    for r in result.get("results", []):
        extra = f"  -> {r['location']}" if r.get("location") else \
                (f"  ({r.get('error', '')})" if r.get("error") else "")
        lines.append(f"  {r['status']:<4} {r['length']:<8} {r['url']}{extra}")
    return "\n".join(lines)