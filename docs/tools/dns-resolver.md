# dns-resolver — DNS Resolver + Cache-Poisoning Lab (W1)

Two modes:

- **resolve** — standard `A, AAAA, MX, NS, TXT, CNAME, SOA, PTR` lookups via
  dnspython (system resolver or a chosen server).
- **poison-lab** — an **in-memory** simulation of DNS cache poisoning.
  A model "caching resolver" shows why transaction-ID + source-port
  randomization defeats spoofed answers. No packets leave your machine.

## What it does NOT do
- The poison-lab never performs a real attack, never queries or sends anything
  to a real resolver, and never binds sockets. It is pure protocol simulation.
- The resolver mode only reads DNS answers.

## Authorized use
- Resolving public DNS is normal operation.
- The poisoning *concept* is for authorized study of DNS defenses only.
  Poisoning a live resolver you do not own is an active attack — never.

## Prerequisites
None (dnspython). The lab needs no network access.

## Usage
```bash
sec-toolkit dns-resolver --mode resolve --domain example.org --types A,MX --json
sec-toolkit dns-resolver --mode resolve --domain example.org --server 1.1.1.1
# lab demo: weak resolver gets poisoned, strong (randomized) resolver does not
sec-toolkit dns-resolver --mode poison-lab --domain victim.test --resolver-mode weak --iterations 200
sec-toolkit dns-resolver --mode poison-lab --domain victim.test --resolver-mode strong --iterations 5000
```

## Output
Resolve: `{records:[{type, ttl, data}], errors:[...]}` with benign failures
(NXDOMAIN, timeout) captured, never raised. Lab: `{accepted, rejected,
acceptance_percent, outcome, explanation}` — weak ≈ 100%, strong ≈ 0% (2×16 bits
of entropy).

## Safety notes
The poison-lab mode is a self-contained in-memory simulation: it sends no
packets and cannot act on any target, so it is safe regardless of the domain
you type. Resolve mode performs ordinary DNS lookups. DNSSEC is not modelled;
treat the strong-mode result as "classic defense against transaction-ID
guessing", not as complete.

## Limitations
- The lab is a simplified model (no cache expiry, no bailiwick rules).
- Resolver mode trusts your DNS path; validate surprising answers yourself.

## Version
0.1.0