# web-fuzzer — Directory & File Discovery (W4)

Brute-forces URL paths against a target web root using a wordlist, reports
which paths exist (by HTTP status) with response sizes, in parallel.

## What it does NOT do
- No payload injection, form fuzzing, or parameter fuzzing.
- No recursive crawling of discovered directories.

## Authorized use
Web discovery: enumerate your own app's / an authorized target's webroot to
map out routes, old endpoints, and files before reviewing them. Fuzzing web
infrastructure you do not own requires written authorization.

## Prerequisites
None. Uses the bundled default wordlist unless `--wordlist` is given.

## Usage
```bash
sec-toolkit web-fuzzer --target-url http://127.0.0.1:8080/ \
    --filter-status 200 --threads 8 --timeout 4
```

## Output
`{target_url, paths_tested, results[]}` with per-hit `{url, status, size,
duration_ms}` and an HTTP `status_counts{}` summary.

## Safety notes
- An authorized-use banner is shown before fuzzing; only fuzz hosts you are
  authorized to test.
- GET-only, single request per path; respects `--threads` and `--timeout`.

## Limitations
- Interior-wordlist scanning only (no content-delivery tricks).
- `/` is probed separately for the landing-page status baseline.

## Version
0.1.0