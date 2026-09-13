# wireguard-vpn — WireGuard VPN Automation (W3)

Orchestrates a WireGuard tunnel around your system's `wg`/`ip` tooling. Three
modes:

- **render** (default, safe): generates server + client `wg-quick`-style
  configs with fresh keypairs and an optional preshared key. 100% pure Python
  (X25519 public-key derivation in-module, verified against the RFC 7748 test
  vector — no system WireGuard needed). Touches nothing.
- **status** (read-only): summarizes `wg show <iface>`.
- **apply** (privileged): builds the interface with `ip` + `wg setconf`.

## What it does NOT do
- Does NOT contact or provision remote peers — it only builds configs/locals.
- Does NOT make your traffic anonymous; WireGuard identifies you by public key
  and normally routes real traffic.
- apply mode requires root/admin and a working WireGuard kernel module; it
  fails fast (never silently) when those are missing.

## Authorized use
Tunnelling between hosts you own (or manage) is normal VPN administration.
Standing up a tunnel that routes another party's traffic through your
infrastructure without their consent is wiretapping-adjacent — use it only for
your own lab hosts. Config generation itself is inert and safe to run anywhere.

## Prerequisites
- render: none (pure stdlib).
- status/apply: `wg` binary (`wireguard-tools`), a `wireguard` kernel module,
  root/admin for apply.

## Usage
```bash
# generate both configs, print them
sec-toolkit wireguard-vpn --mode render --role server \
  --self-address 10.66.0.1/24 --peer-address 10.66.0.2/32

# write them out for hand-off
sec-toolkit wireguard-vpn --mode render --role server \
  --output-dir ./wg-configs

# client config with a real endpoint
sec-toolkit wireguard-vpn --mode render --role client \
  --endpoint vpn.example.com:51820

# inspect a live interface (needs wg)
sec-toolkit wireguard-vpn --mode status --interface wg0

# configure + bring up the interface (needs root)
sudo sec-toolkit wireguard-vpn --mode apply --interface wg0
```

## Output
render → `{own:{private,public}, peer:{private,public}, preshared_key,
server_config, client_config}` plus `written_to` when `--output-dir` is set.
status → `{status_text}` from `wg show`. apply → adds `applied: true`.

## Safety notes
- Local interface configuration only; only ever touch your own host's
  interfaces. `apply` brings up an interface — use it only on systems you own.
- Fresh keys every run — flagged in the result; save keys you actually use.
- apply refuses non-root with a clear `PermissionError`; missing `wg` fails
  fast for status/apply; render never executes system commands.
- `preshared_key` is only ever accepted through params and never logged raw
  (secrets are redacted by the CLI layer).

## Limitations
- Generates RFC 7748 / IPv4-focused configs; IPv6 supported in `allowed_ips`
  parsing. No wg-quick routing rules (Table/PostUp/PostDown) generated.
- Public-key derivation is pure Python (educational-speed X25519; fine for
  keygen, not a performance engine).
- apply does not clean up on partial failure (a failed step leaves a down
  interface; `ip link del` to retry).

## Version
0.1.0