# Permissions Matrix — Security Toolkit Suite

Which tools need which privileges, and what to do when you lack them.

## Legend

- **none** — runs unprivileged on all platforms.
- **net_raw** — raw sockets: Linux `CAP_NET_RAW` or root; Windows/macOS administrator.
- **root** — effectively CAP_NET_RAW; see net_raw.
- **admin** — OS administrator rights (Windows `IsUserAnAdmin`).

Tools that *declare* `net_raw` fail fast with a clear message when the
capability is missing. They never silently degrade into an unprivileged,
half-working scan.

| Tool | Wave | Privilege | Needs privileges for |
|---|---|---|---|
| subnet-calc | W1 | none | — (pure computation) |
| arp-scan | W1 | net_raw | sending ARP packets on the local Ethernet segment |
| port-scan | W1 | none / net_raw | `syn` mode only; `tcp_connect`/`version` need none |
| dns-resolver | W1 | none | — (`poison-lab` is an in-memory simulation) |
| packet-sniff | W1 | net_raw | `live` capture only; `offline` PCAP needs none |
| hids-agent | W2 | none | — (processes mode reads `/proc`; integrity is pure stdlib) |
| firewall-audit | W2 | none (cmd-level) | `iptables-save`/`nft` need root to read the ruleset; degrades to a port report when unavailable |
| log-anonymize | W2 | none | — (writes only the output file you choose) |
| honeypot | W2 | none | plain TCP listener; binds to the host you choose (authorized-use banner shown) |
| port-forward | W3 | none | TCP/UDP relay between bind and target host you choose (authorized-use banner shown) |
| http-proxy | W3 | none | binds and proxies to target host you choose (authorized-use banner shown) |
| socks5-proxy | W3 | none | binds and CONNECTs/UDP-relays to target host you choose (authorized-use banner shown) |
| wireguard-vpn | W3 | root (apply only) | local interface config; `status`/`apply` require the `wg` binary; `apply` requires root; render is pure config |
| vuln-scanner | W4 | none | banner grab + CVE match against the host/ports you choose; reads banners only |
| web-fuzzer | W4 | none | GET-only path discovery against the target URL you choose; bounded wordlists |
| sqli-detector | W4 | none | error/time payloads against the target URL you choose; small bounded payload sets |
| password-auditor | W4 | none | read-only (audit + offline dictionary crack); no network |
| disk-image | W5 | none | read-only hashing/verify; `image` mode copies to the output dir you choose |
| memory-forensics | W5 | none | read-only; `vol` mode shells out to the `vol` binary (180 s timeout) |
| deleted-recovery | W5 | none | read-only against source; writes carved files under output dir |
| browser-artifacts | W5 | none | read-only sqlite reads; writes the JSON report you ask for |
| android-forensics | W5 | none | read-only; decrypts nothing (encrypted backups refused); extracts only to the output dir |
| static-analysis | W6 | none | read-only sample parsing; writes the JSON report you ask for |
| yara-rulegen | W6 | none | read-only; rule/classify output is string-presence only |
| unpack-tool | W6 | none | read-only; UPX decode refused (header detection only) |
| persistence-catalog | W6 | none | scans only the directory tree you pass; read-only |
| c2-extractor | W6 | none | read-only; never contacts extracted domains/IPs |
| privesc-enum | W7 | none | reads local SUID/writable-dir/dir PATH/passwd; read-only; report only to your output dir |
| buffer-overflow | W7 | none | local math + file generation only; never touches the network |
| metasploit-module | W7 | none | writes `.rb` skeleton only; never runs the framework or connects |
| c2-obfuscation | W7 | none | local demo only; writes payload.bin + deobfuscator.py to your output dir |
| c2-jitter | W7 | none | pure scheduling math; writes beacon-timeline.csv to your output dir |
| persistence-rules | W7 | none | reads only the catalog JSON / tree you pass; writes Sigma YAML to your output dir |
| burp-extension | W8 | none | writes a local `.py` skeleton only; never proxies or connects |
| wireless-wpa-audit | W8 | none | offline pcap read; writes the JSON report you ask for; no radio, no deauth, no injection |

## How to grant raw sockets on Linux

```bash
# Option A: run the single scan as root
sudo .venv/bin/sec-toolkit arp-scan --subnet 192.168.1.0/24

# Option B (preferred): give only this binary CAP_NET_RAW
sudo setcap cap_net_raw,cap_net_admin+ep .venv/bin/python
```

Option B keeps your normal workflow unprivileged. Do **not** run your whole
desktop session or browsing as root to enable a scanner.

## Windows / macOS

Raw packet tools (ARP scan, SYN scan, live sniff) require an elevated
(administrator) console and Ethernet interfaces. If a VM or container is
available, prefer running these inside it.

## GUI vs CLI

The GUI runs tools in a background thread within your user session. When a tool
needs privileges you lack, it shows the same clear "denied" dialog the CLI
prints. For live capture/ARP tests, launch `sec-toolkit-gui` from an elevated
terminal. Keep `subnet-calc`, `port-scan` (tcp_connect), and `dns-resolver`
unprivileged as normal-day tools.