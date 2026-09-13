# arp-scan — ARP Scanner (W1)

Discover live Layer-2 neighbors and their MAC addresses on a local Ethernet
segment by broadcasting ARP requests.

## What it does NOT do
- Does not leave the local segment (ARP never crosses routers).
- Does not port-scan, exploit, or modify targets.
- Does not resolve MAC vendors (no OUI database shipped).

## Authorized use
Scan **your own** subnets, or subnets you are explicitly contracted/tested to
assess. ARP scanning a network you do not own may be an offense.

## Prerequisites
Raw sockets: Linux `CAP_NET_RAW`/root, Windows/macOS admin. See
`docs/permissions.md`.

## Usage
```bash
sec-toolkit arp-scan --subnet 192.168.1.0/24 --timeout 3 --resolve-hosts --save-csv --json
```

## Output
List of `{ip, mac, hostname, responder}` plus `scan_count` and duration.
Optional CSV report in the configured output dir. JSON via `--json`.

## Safety notes
- Broadcast sweep is visible to all hosts on the segment — expect a response
  from monitoring systems.
- Subnets with more than 65,536 addresses are refused.

## Limitations
- Requires a plain L2 Ethernet interface; Wi-Fi clients may see odd results
  (AP isolation hides stations).
- Slow interfaces / firewalled endpoints may not answer.

## Version
0.1.0