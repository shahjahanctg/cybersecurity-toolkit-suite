# honeypot — Honeypot (SSH/HTTP trap) (W2)

Interactive trap listener that emulates a weak SSH service (fake OpenSSH
banner, no crypto) or a weak HTTP service (fake Apache), capturing connection
fingerprints and recorded credential probes.

## What it does NOT do
- Does NOT run a real SSH server or complete a real TLS/KEX handshake.
- Does NOT test, attack, or reach out to any remote host — it only listens.
- Does NOT store plaintext beyond the transcript buffer and report you choose
  to write; captured bytes are capped at 64 hex chars in reports.

## Authorized use
A honeypot is a *deception* tool: it looks like a vulnerable service to
observers. Binding one inside your own lab/network to study scanning and
attack tooling is a legitimate defensive practice. Binding it on a network you
do not control is an attack on third parties and is illegal.

## Prerequisites
None (pure standard library). Requires an unused TCP port for the chosen
service. Default bind is `127.0.0.1`.

## Usage
```bash
# SSH trap on loopback 8022, run 2 minutes
sec-toolkit honeypot --proto ssh --host 127.0.0.1 --port 8022 --duration 120

# HTTP trap, then it saves a JSON report to the output dir
sec-toolkit honeypot --proto http --port 8080 --duration 60 --save-report --json

# run until you hit Ctrl-C (0 = indefinite, cancelled cleanly)
sec-toolkit honeypot --proto ssh --duration 0
```

## Output
Per connection: `{cid, client, client_port, fingerprint, handshake_hex}` plus
- **ssh**: `client_banner` + `probes` (printable-ASCII keywords such as
  `root`, `password`, `admin` found in the handshake payload).
- **http**: request line, method/path, `user_agent`, `auth_scheme` +
  `auth_user` (Basic credentials decoded from `Authorization`), `header_count`.
Fingerprint guesses: libssh/paramiko, OpenSSH, PuTTY, Dropbear, curl, sqlmap,
nikto, wpscan, Python/Go HTTP clients, etc.

The full connection list is returned + written as a JSON report when
`--save-report` is on.

## Safety notes
- An authorized-use banner is shown before the trap starts; only bind it on
  networks you own/are authorized to monitor.
- The report line caps raw handshake bytes at 64 hex chars per connection to
  limit stored data; clear reports you no longer need.
- Uses `SO_REUSEADDR` so restart after Ctrl-C is immediate.

## Limitations
- SSH mode never completes a key exchange, so it only fingerprints banners and
  payload text; it cannot capture later-stage auth exchanges.
- Basic-auth capture is heuristic (base64 decode of `Authorization`); token
  schemes are flagged but not decoded.
- Single-service per run; a dual-port setup means two runs.

## Version
0.1.0