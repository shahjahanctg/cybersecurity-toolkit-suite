# socks5-proxy — SOCKS5 Proxy (no-auth) (W3)

Minimal forward SOCKS5 proxy per RFC 1928 (no-auth subset): `CONNECT`
byte tunnels and `UDP ASSOCIATE` datagram relay. Every connection is logged.

## What it does NOT do
- No username/password (GSSAPI/plaintext auth) — a client offering only auth
  methods is refused (`0xFF`) and closed.
- No BIND command (RFC 1928 0x02) — answered with `REP 0x07`, logs
  `501`.
- No sniffing/decryption of tunnelled TLS — bytes are relayed untouched.

## Authorized use
Standard pivot device: point a browser/tool's SOCKS5 client at
`127.0.0.1:<port>` to reach services through a stable tunnel endpoint. Using
it to reach infrastructure you do not own requires written authorization.

## Prerequisites
None (pure standard library). Default listen port 1080.

## Usage
```bash
# run the proxy for 5 minutes
sec-toolkit socks5-proxy --listen-port 1080 --duration 300

# tell a client to use it, e.g.
#   curl --socks5 127.0.0.1:1080 http://127.0.0.1/
#   curl --socks5-hostname 127.0.0.1:1080 http://127.0.0.1/
#   export ALL_PROXY=socks5h://127.0.0.1:1080
```

## Output
`{listen, connections, active_connections, requests_log[]}` with per-connection
`{client, command, target, status}` (status 200 = ok, 502 = refused, 501 =
unsupported command). Log bounded to 200 entries.

## Safety notes
- An authorized-use banner is shown before the proxy starts; only relay
  traffic you are authorized to forward.
- UDP ASSOCIATE's request address is a `0.0.0.0:0` sentinel — the real
  destination is taken from inside each datagram.
- Control connection must stay open for the lifetime of a UDP relay (this is
  how SOCKS5 clients signal liveness); closing it tears the relay down.

## Limitations
- IPv6-assigned targets supported for parsing; the relay binds IPv4.
- No fragmentation reassembly: SOCKS UDP frames with `FRAG != 0` are dropped.
- Reply classification assumes destination replies are not themselves valid
  SOCKS UDP frames; a destination payload beginning `\x00\x00\x00...` may be
  misread on a rare edge case.
- No proxy authentication, no keep-alive pooling for TCP, no TCP-over-UDP.

## Version
0.1.0