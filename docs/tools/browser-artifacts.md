# browser-artifacts — Browser Artifacts (W5)

Extracts recent history URLs and cookies from a Firefox or Chrome profile
directory (SQLite) and optionally dumps the result to a JSON report.
Firefox fully supported; Chrome's databases are opened read-only and the
tool degrades gracefully when the browser holds a lock.

## What it does NOT do
- No cache carving/decode, form history, or profile keychain decryption.
- No Chrome cookie value decryption (App-Bound Encryption keys aren't read) —
  Chrome cookie values are reported as `<encrypted>`.
- Never modifies the profile.

## Authorized use
Investigating browsing artifacts on machines you own or are authorized to
analyze (e.g. your own forensics lab images). Browser data is personal data —
handle in line with your org's policy.

## Prerequisites
None (stdlib `sqlite3`). Close the target browser for stable, complete reads.

## Usage
```bash
# auto-detect from the profile folder contents
sec-toolkit browser-artifacts --profile-dir ~/.mozilla/firefox/xxxx.default

# force a browser and write a JSON report
sec-toolkit browser-artifacts --profile-dir ./chrome-profile \
    --browser chrome --output-file ./artifacts.json --max-rows 500
```

## Output
`{browser, profile, count, rows[]}` — `url` rows carry
`{url, title, visit_count, last_visit}`; `cookie` rows carry
`{name, host, path, ...}`; lock failures surface as `error` rows so the
report explains itself.

## Safety notes
- SQLite connections are opened read-only (`mode=ro`).
- Output JSON is written only where you point it.

## Limitations
- Firefox is the completeness baseline; Chrome visits are webkit-time
  converted, cookie values stay encrypted, and locked DBs degrade to `error`
  rows instead of partial reads.
- Only `moz_places`/`moz_cookies` and `urls`/`cookies` tables are parsed.

## Version
0.1.0