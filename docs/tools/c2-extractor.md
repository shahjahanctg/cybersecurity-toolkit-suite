# c2-extractor — C2 Beacon Extractor (W6)

Hunts callback/c2 indicators in a sample or memory dump: domain literals,
IP literals (RFC1918 excluded by default), beacon timing keywords
(`jitter`, `sleep`, `beacon`, `interval`, ...) with adjacent values, HTTP
user-agent / cookie remnants, and URL-path lists.

## What it does NOT do
- No decoded beacon conference-call parsing, no key extraction, no domain
  reputation / enrichment.
- Everything reported is a *candidate* for human review — this is a hunting
  aid, not a verdict engine.

## Authorized use
Threat-hunting on samples and dumps you are authorized to analyze. Do not
resolve or touch callback domains from this tool — that can be unsafe.

## Prerequisites
None.

## Usage
```bash
sec-toolkit c2-extractor --sample ./dump.bin --output-file ./c2.json

# include lab/RFC1918 hosts
sec-toolkit c2-extractor --sample ./dump.bin --include-private-ips
```

## Output
`{domains[], ip_literals[], timings[], http_remnants[], url_paths[],
candidate_count, output_file?}`.

## Safety notes
- Read-only against the sample.
- The tool never contacts extracted domains/IPs.

## Limitations
- Domain regex may emit bogus tokens from dense binary data; the single-label
  guard removes obvious noise but eyeball the list.
- Private IPs are hidden by default because lab malware frequently records
  internal demos — use `--include-private-ips` for full triage.

## Version
0.1.0