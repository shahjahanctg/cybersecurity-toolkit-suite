# firewall-audit — Firewall Auditor (W2)

Read-only posture audit of the host firewall: chain policies, rule counts,
jump targets, listening ports, and permissive-policy warnings.

## What it does NOT do
- Does not modify firewall state (no rules added/removed).
- Does not connect to remote targets — local host only.
- Windows ruleset is reported in brief only (no per-rule parsing yet).

## Authorized use
Reading your own host's firewall configuration is normal administration.
`iptables-save`/`nft` output can reveal network topology, so only forward
results you are allowed to share.

## Prerequisites
- **Linux iptables backend**: `iptables-save` (root usually required).
- **Linux nftables backend**: `nft` (root usually required).
- **Listening ports**: none — parsed from `/proc/net/tcp{,6}`.
- If the ruleset command is missing or unprivileged, the tool degrades to the
  listening-port report instead of failing outright.

## Usage
```bash
sec-toolkit firewall-audit --backend auto                     # best effort
sec-toolkit firewall-audit --backend nftables --json          # structured
sec-toolkit firewall-audit --backend windows --check-listening
```

## Output
Per-table-per-chain `{table, chain, policy, rule_count, targets}`, plus
`listening_ports` (proto, port, service, addr) and `warnings` for permissive
INPUT policies and common attack-surface services (22, 23, 3389, 5900, 445,
139, 512–514, 2049).

## Safety notes
- Backends are read-only; the only side effect is writing the selected JSON
  envelope to the result file if you enable it.
- `ruleset_error` is populated instead of crashing when privileges are missing.

## Limitations
- `iptables-save` and `nft list ruleset` are text-based; parsers target their
  canonical output formats.
- IPv6 rows, kernel-comment rules and `-m` extensions are surfaced as counts,
  not fully interpreted.
- Windows parsing is intentionally minimal (raw line count, listening ports).

## Version
0.1.0