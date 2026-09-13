# packet-sniff — Packet Sniffer (W1)

Capture and summarize packets on an interface (live) or analyze a saved PCAP
file (offline). Supports BPF-style filters and saving captures.

## What it does NOT do
- Does not decrypt TLS/HTTPS payloads.
- Does not reassemble flows or extract files.
- Offline mode reads only the given file.

## Authorized use
Capturing traffic you are not authorized to observe may be illegal and is
almost always visible to the network. Only sniff your own hosts/segments or
networks with written monitoring authorization.

## Prerequisites
- **live**: raw sockets (`CAP_NET_RAW`/root, admin on Windows/macOS).
- **offline**: none — analyze any PCAP you may legally hold.

## Usage
```bash
# live, 10 seconds on eth0 filtering web traffic
sec-toolkit packet-sniff --mode live --interface eth0 --filter "tcp port 80" --timeout 10 --save-pcap ./captures --json

# offline analysis of a captured file
sec-toolkit packet-sniff --mode offline --pcap-file traffic.pcap --filter tcp
```

## Output
Per-packet summary `{time, src, dst, proto, sport, dport, length, payload}`
(`payload` is a short UTF-8/hex sample). Plus counts and, for live mode with
`save_pcap`, a `.pcap` file. Deterministic offline (same file → same summary).

## Safety notes
- Live capture requires the same capability an ARP scan does — grant only
  `CAP_NET_RAW`, not a root-everything setup (see `docs/permissions.md`).
- Summaries keep the first 200 chars of payloads; that is still data capture —
  clear results you do not need.

## Limitations
- BPF filter support is a hand-rolled subset (`tcp`, `udp`, `icmp`, `ip`,
  `port N`); complex expressions are not compiled through libpcap.
- In-memory summary cap is 5,000 packets to bound memory for long runs.

## Version
0.1.0