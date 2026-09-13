# vuln-scanner — Banner Grab + CVE Match (W4)

Fingerprints a TCP service by banner and matches the result against a small
bundled rule set (10 curated CVEs). Scans several ports in parallel.

## What it does NOT do
- No active exploit attempts of any kind.
- No Nmap-style packet-level probing; only a banner read after connect.
- Rule set is a curated list (`data/cves.json`) — this is not a full
  CVE database, and an empty banner produces no match.

## Authorized use
Vulnerability triage: point it at your own services or authorized targets and
identify the exact version banner so you can look up fixes. Scanning hosts you
do not own requires written authorization.

## Prerequisites
None (pure standard library). Rules can be overridden with `--rules-json`.

## Usage
```bash
# scan a single port
sec-toolkit vuln-scanner --host 127.0.0.1 --ports 2222

# scan a range and a couple of singles in parallel
sec-toolkit vuln-scanner --host 127.0.0.1 --ports 22,80,443,8080-8090 \
    --timeout 3 --threads 8
```

## Output
`{host, scanned_ports, results[]}` — per port `{port, service, banner,
fingerprint:{product, version}, rules_matched[], matched_cves[]}`.
A service name is guessed from the banner when possible (`ssh`, `http`, ...);
CVE rules are version-comparison filtered + host-filtered (e.g. an Apache
match only applies on a host serving Apache banners).

## Safety notes
- An authorized-use banner is shown before connecting; only scan hosts you
  are authorized to test.
- Only sends the service's own greeting; never writes payloads to the peer.
- Banner output is decoded and truncated for logging.

## Limitations
- Service guess is banner-only; synthetic banners may be misclassified.
- Matches depend on the bundled rule granularity (see `data/cves.json`).
- Not a threaded/performance scanner: bounded by `--threads` (default 8).

## Version
0.1.0