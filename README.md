# Security Toolkit Suite

A desktop **GUI + CLI** suite of cybersecurity tools organised into delivery
waves: network recon, defense & monitoring, proxy/tunnel, vulnerability
scanning, forensics, malware analysis, red-team/C2, and extras.

> **Authorized use only.** Every tool in this suite is meant to run against
> systems **you own** or **hold explicit written authorization to test**.
> Unauthorized scanning, capture, or testing may be a criminal offense. Read
> [`docs/permissions.md`](docs/permissions.md) and each tool's doc before use.

---

## Status

| Wave | Domain | Priority | State |
|---|---|---|---|
| **W1** | Network Recon | P0 | ✅ **Delivered** (5 tools) |
| **W2** | Defense & Monitoring | P1 | ✅ **Delivered** (4 tools) |
| W3 | Proxy & Tunnel | P1 | ✅ **Delivered** (4 tools) |
| W4 | Vuln Scanning | P1 | ✅ **Delivered** (4 tools) |
| W5 | Forensics | P2 | ✅ **Delivered** (5 tools) |
| W6 | Malware Analysis | P2 | ✅ **Delivered** (5 tools) |
| W7 | Red Team / C2 | P2 | ✅ **Delivered** (6 tools) |
| W8 | Extras | P3 | ✅ **Delivered** (2 tools) |

Waves are delivered and reviewed one at a time. W1 is complete end-to-end:
tool logic, CLI wiring, GUI pages, tests, and docs. W2 is complete as well:
HIDS agent, firewall audit, log anonymizer, and the SSH/HTTP honeypot.
W3 (Proxy & Tunnel) has landed: port forwarder, HTTP proxy, SOCKS5 proxy, and
WireGuard VPN automation. W4 (Vuln Scanning) is complete: banner-grab + CVE
scanner, web fuzzer, SQLi detector, and password auditor/cracker. W5
(Forensics) is complete: disk imaging + chain of custody, memory forensics,
deleted-file carving, browser artifacts, and Android `.ab` parsing. W6
(Malware Analysis) is complete: static analysis pipeline, YARA rulegen +
classifier, unpacking/deobfuscation practice, persistence cataloging, and C2
beacon extraction. W7 (Red Team / C2) is complete: privesc enumeration,
buffer-overflow walkthrough, Metasploit module generator,
C2 obfuscation study, C2 jitter/sleep study, and persistence detection rules.
W8 (Extras) rounds out the suite at **35 tools**: the Burp Suite extension
generator and the offline wireless WPA2 handshake/PMKID auditor.

## Tool index (W8 — Extras)

| Tool | CLI name | Privileges | Docs |
|---|---|---|---|
| Custom Burp Suite Extension (Jython) | `burp-extension` | none | [docs](docs/tools/burp-extension.md) |
| Wireless Auditor (WPA2 Handshake / PMKID) | `wireless-wpa-audit` | none | [docs](docs/tools/wireless-wpa-audit.md) |

## Tool index (W7 — Red Team / C2)

| Tool | CLI name | Privileges | Docs |
|---|---|---|---|
| Privilege Escalation Enum | `privesc-enum` | none | [docs](docs/tools/privesc-enum.md) |
| Buffer Overflow Walkthrough | `buffer-overflow` | none | [docs](docs/tools/buffer-overflow.md) |
| Custom Metasploit Module Generator | `metasploit-module` | none | [docs](docs/tools/metasploit-module.md) |
| C2 Traffic Obfuscation Demo | `c2-obfuscation` | none | [docs](docs/tools/c2-obfuscation.md) |
| C2 Check-in Jitter / Sleep Study | `c2-jitter` | none | [docs](docs/tools/c2-jitter.md) |
| Persistence Catalog + Detection Rules | `persistence-rules` | none | [docs](docs/tools/persistence-rules.md) |

## Tool index (W6 — Malware Analysis)

| Tool | CLI name | Privileges | Docs |
|---|---|---|---|
| Static Analysis Pipeline (PE/ELF) | `static-analysis` | none | [docs](docs/tools/static-analysis.md) |
| YARA Rule Generator + Classifier | `yara-rulegen` | none | [docs](docs/tools/yara-rulegen.md) |
| Unpacking / Deobfuscation Practice | `unpack-tool` | none | [docs](docs/tools/unpack-tool.md) |
| Persistence Cataloger (IOC scan) | `persistence-catalog` | none | [docs](docs/tools/persistence-catalog.md) |
| C2 Beacon Extractor | `c2-extractor` | none | [docs](docs/tools/c2-extractor.md) |

## Tool index (W5 — Forensics)

| Tool | CLI name | Privileges | Docs |
|---|---|---|---|
| Disk Image Acquirer (chain of custody) | `disk-image` | none | [docs](docs/tools/disk-image.md) |
| Memory Forensics (Volatility 3 + strings) | `memory-forensics` | none | [docs](docs/tools/memory-forensics.md) |
| Deleted File Recovery (signature carving) | `deleted-recovery` | none | [docs](docs/tools/deleted-recovery.md) |
| Browser Artifacts (Firefox/Chrome) | `browser-artifacts` | none | [docs](docs/tools/browser-artifacts.md) |
| Android Forensics (adb backup parser) | `android-forensics` | none | [docs](docs/tools/android-forensics.md) |

## Tool index (W4 — Vuln Scanning)

| Tool | CLI name | Privileges | Docs |
|---|---|---|---|
| Banner Grab + CVE Match | `vuln-scanner` | none | [docs](docs/tools/vuln-scanner.md) |
| Web Directory Fuzzer | `web-fuzzer` | none | [docs](docs/tools/web-fuzzer.md) |
| SQLi Detector (error + time) | `sqli-detector` | none | [docs](docs/tools/sqli-detector.md) |
| Password Auditor & Cracker | `password-auditor` | none | [docs](docs/tools/password-auditor.md) |

## Tool index (W3 — Proxy & Tunnel)

| Tool | CLI name | Privileges | Docs |
|---|---|---|---|
| Port Forwarder (TCP/UDP relay) | `port-forward` | none | [docs](docs/tools/port-forward.md) |
| HTTP Proxy (GET + CONNECT) | `http-proxy` | none | [docs](docs/tools/http-proxy.md) |
| SOCKS5 Proxy (no-auth) | `socks5-proxy` | none | [docs](docs/tools/socks5-proxy.md) |
| WireGuard VPN Automation | `wireguard-vpn` | root* (apply only) | [docs](docs/tools/wireguard-vpn.md) |

## Tool index (W2 — Defense & Monitoring)

| Tool | CLI name | Privileges | Docs |
|---|---|---|---|
| HIDS Agent (integrity + processes) | `hids-agent` | none | [docs](docs/tools/hids-agent.md) |
| Firewall Auditor | `firewall-audit` | none (iptables/nft need root to read) | [docs](docs/tools/firewall-audit.md) |
| Log Anonymizer | `log-anonymize` | none | [docs](docs/tools/log-anonymize.md) |
| Honeypot (SSH/HTTP trap) | `honeypot` | none | [docs](docs/tools/honeypot.md) |

---

## Quick start

```bash
# from the repository root
make install          # creates .venv and installs package + GUI + tests

# CLI
.venv/bin/sec-toolkit list
.venv/bin/sec-toolkit subnet-calc --cidr 192.168.1.0/24
.venv/bin/sec-toolkit subnet-calc --cidr 10.0.0.0/22 --mode vlsm --hosts 100,50,25,12 --json

# GUI (dark theme)
.venv/bin/sec-toolkit-gui

# tests (headless)
make test
```

Requires **Python 3.11+** (developed on 3.14). Dependencies: `scapy`,
`dnspython`; GUI extra: `PySide6`.

---

## Tool index (W1 — Network Recon)

| Tool | CLI name | Privileges | Docs |
|---|---|---|---|
| Subnet / VLSM Calculator | `subnet-calc` | none | [docs](docs/tools/subnet-calc.md) |
| ARP Scanner | `arp-scan` | net_raw | [docs](docs/tools/arp-scan.md) |
| Port Scanner (TCP/SYN/version) | `port-scan` | none / net_raw (syn) | [docs](docs/tools/port-scan.md) |
| DNS Resolver + Cache-Poisoning Lab | `dns-resolver` | none | [docs](docs/tools/dns-resolver.md) |
| Packet Sniffer | `packet-sniff` | net_raw (live) | [docs](docs/tools/packet-sniff.md) |

Full privilege details: [`docs/permissions.md`](docs/permissions.md).

---

## Design guarantees

- **Structured output** — every tool supports `--json`; the GUI shows text + JSON
  with export/copy.
- **Fail-fast privileges** — raw-socket tools refuse to run half-working and
  tell you exactly what capability is missing.
- **Safety rails** — every network-touching or destructive tool opens with an
  authorized-use banner; destructive tools also require confirmation, and
  raw-socket tools warn when capabilities are missing.
- **Secret redaction** — the logger scrubs password/key/token fields from
  run envelopes and log lines.
- **Cooperative cancellation** — SIGINT (CLI) or **Cancel** (GUI) stops scans
  predictably.
- **Tests for everything** — including the "simple" arithmetic tools.

---

## Architecture

See [`ARCHITECTURE.md`](ARCHITECTURE.md). In short: every tool is one module
declaring a `ToolMeta` (name, wave, privileges, fields, safety flags) and a
`run(params, ctx)` function. The CLI and GUI are both generated from that single
contract, so a tool wired once is available everywhere.

```
src/sectoolkit/{cli,core,gui,tools/<wave>}   tests/{core,tools,gui,integration}   docs/
```

---

## Isolated lab / Docker

```bash
docker build -t sec-toolkit:lab .
docker run --rm -it --cap-add NET_RAW sec-toolkit:lab sec-toolkit list
```

The container is a disposable lab for raw-socket work. Never treat it as a
hardened environment or point it at production networks.

---

## Safety & legal

1. Run tools **only** against systems you own or are authorized to test.
2. Network-touching and destructive tools print an **authorized-use banner**
   on every run, before anything is sent or changed.
3. No credentials, API keys, or sample malware are shipped in this repository.
4. Every tool documents what it does **and does not** do.
5. Destructive/offensive waves (W5–W8) will require explicit lab context before
   implementation.

This suite is a tooling project, not legal advice. Apply your organization's
policy and local law.

---

## Roadmap / contributing

All 8 waves are delivered end-to-end (35 tools): logic, CLI wiring, GUI pages,
tests, and docs. Next: only final QA passes (audit + smoke) before release.
Keep new tools on the `ToolMeta` + `run(params, ctx)` contract and add at
least happy-path, error, and privilege tests.

## License

MIT. Provided as-is, with no warranty and no authorization to use it against
systems you do not control.
