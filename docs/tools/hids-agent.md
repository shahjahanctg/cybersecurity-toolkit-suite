# hids-agent — HIDS Agent (W2)

Host integrity monitoring with three modes:
- **baseline** — snapshot file hashes/sizes/mtimes for chosen paths into a JSON
  baseline you point at (read-only against the tree).
- **check** — diff the live tree against a baseline; report added, removed,
  modified files with old vs new metadata.
- **processes** — snapshot running processes (Linux `/proc`, read-only).

## What it does NOT do
- No kernel hooks, inotify/fanotify, or real-time watching.
- No ability to block or quarantine anything.
- No behavioral/network detection — hashing only, for the paths you choose.

## Authorized use
Monitoring your own systems is normal administration. A baseline of shared
binaries is useful in incident response; store baselines you hold as evidence
securely.

## Prerequisites
None for integrity checks (pure stdlib). The `processes` mode requires Linux
`/proc`.

## Usage
```bash
# 1. capture a baseline of /etc and your PATH binaries
sec-toolkit hids-agent --mode baseline --paths /etc,/usr/local/bin --baseline baselines/etc.json
# 2. later, detect change
sec-toolkit hids-agent --mode check --baseline baselines/etc.json --exclusions .lock,.pid --json
# 3. process snapshot
sec-toolkit hids-agent --mode processes
```

## Output
- baseline: `files_recorded` + the JSON baseline `{schema, algorithm, created_at, files}`.
- check: `integrity` (`CLEAN`/`CHANGED`), `added`, `removed`, `modified` (old
  vs new size/mtime/sha256), `scanned_files`, `duration_ms`.
- processes: `{pid, comm, state, uid, exe}` list.

## Safety notes
- Skips symlinks (no loops, no escapes via links).
- Unreadable files record an empty hash — visible in `modified` so you can
  review instead of silently missing content.
- `max_files` (default 20,000) bounds runtime and output size.

## Limitations
- Baseline paths are stored as given; moving the tree breaks relativity.
- Reading some protected files requires privilege; missing hashes are flagged,
  not fatal.
- The whole-tree hash walk is slower than event-based watchers by design;
  watch only what matters.

## Version
0.1.0