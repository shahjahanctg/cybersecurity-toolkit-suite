# port-scan — Port Scanner TCP / SYN / version (W1)

Scan a host for open ports with three modes:

| scan_type | handshake | privileges | notes |
|---|---|---|---|
| `tcp_connect` | full connection | none | reliable, slow, logged by target |
| `syn` | half-open (SYN/SYN-ACK) | net_raw | fast, stealthier, may be filtered |
| `version` | connect + banner read | none | identifies service + grabs banner |

## What it does NOT do
- Does not exploit open ports.
- Does not scan beyond the stated host + port list.
- Banner grab is passive read-only after connect.

## Authorized use
Only hosts you own or are authorized to assess. Unauthorized port scanning is
monitored by most networks and is illegal in many jurisdictions.

## Prerequisites
`syn` mode needs raw sockets (`CAP_NET_RAW`/root, Windows/macOS admin).
`tcp_connect` and `version` need none.

## Usage
```bash
sec-toolkit port-scan --host 10.0.0.5 --ports 22,80,443,8080
sec-toolkit port-scan --host 10.0.0.5 --ports 1-1024 --scan-type syn --threads 300 --json
sec-toolkit port-scan --host 10.0.0.5 --ports 80,443 --scan-type version
```

## Output
`{host, scan_type, open_count, results:[{port, state, service, banner}]}`.
`service` is an IANA best-effort name for common well-known ports. Closed ports
are dropped from the human table but present in JSON.

## Safety notes
- Rate: keep `--threads` modest on real scans; default 200.
- Timeout is capped at 30 s.
- Version-mode banner reads are bounded (2 KiB) and UTF-8-sanitized; a hostile
  service could still speak plenty — treat banners as unverified data.

## Limitations
- SYN results depend on your network position; "filtered" vs "closed" is
  best-effort.
- Service names cover a small well-known set only.

## Version
0.1.0