# sqli-detector — SQL Injection Detection (W4)

Finds SQL injection in one target URL using bounded error-signature and
time-based boolean-blind payload sets. Use a `{fuzz}` placeholder in the URL
or let it test every query parameter.

## What it does NOT do
- No exploitation/dumping — only detection probes small payload sets.
- No OAST/out-of-band checks, no stacked-query attacks on the wire beyond
  the passive `WAITFOR/pg_sleep` timing probes.

## Authorized use
Web-app testing on systems you own or are explicitly authorized to test.
Testing applications you do not own requires written authorization.

## Prerequisites
None (standard library HTTP client). Bounded `delay_s` (>= 1) for timing.

## Usage
```bash
# explicit placeholder
sec-toolkit sqli-detector --target-url 'http://127.0.0.1:8080/item?id={fuzz}'

# auto-scan every query parameter
sec-toolkit sqli-detector --target-url 'http://127.0.0.1:8080/search?q=x&cat=1' \
    --payload-set stock --error-based --time-based --delay-s 3
```

## Output
`{target_url, candidates_tested, requests, findings[]}` — each finding
`{parameter, kind (error-based|time-based), payload, db_engine[], evidence}`.

## Safety notes
- An authorized-use banner is shown before probing; use it only against
  hosts you are authorized to test.
- Payloads are URL-encoded before sending.
- Time-based probes never sleep remotely beyond `--delay-s` (default 3).

## Limitations
- Blind detection is confidence-only; a non-SQL app echoing an SQL-looking
  error can produce a false positive.
- Time-based requires the target to actually block on `SLEEP`.

## Version
0.1.0