# http-proxy — HTTP Proxy (GET + CONNECT) (W3)

Minimal forward HTTP proxy: relays absolute-form HTTP requests to origin
hosts and tunnels raw bytes for `CONNECT` (TLS-passthrough). Every request is
logged with client, method, target, user-agent, and status.

## What it does NOT do
- Does NOT decrypt/read TLS — CONNECT relays bytes unchanged.
- Does NOT cache, filter, or rewrite content; hop-by-hop headers are stripped
  before forwarding (RFC 7230-conformant forward proxy).

## Authorized use
Set your client's proxy to `127.0.0.1:<port>` to record traffic to authorized
destinations. Proxying arbitrary web traffic (e.g., capturing third-party
sessions) requires authorization.

## Prerequisites
None (pure standard library). Unused listen port (default 8080).

## Usage
```bash
# run the proxy, log to the console for 10 minutes
sec-toolkit http-proxy --listen-port 8080 --duration 600

# point a client at it, e.g.
#   curl -x http://127.0.0.1:8080 http://127.0.0.1:80/
# some CONNECT-using client (HTTPS proxying / tunnelling)
```

## Output
`{listen, requests, requests_log[]}` with `{client, method, target,
user_agent, status}` per request. The request log is bounded to 500 entries in
memory; nothing is written to disk by default (the JSON envelope is available
with `--json`).

## Safety notes
- An authorized-use banner is shown before the proxy starts; only proxy
  traffic you are authorized to forward.
- Universal `Accept` of credentials is not performed — this proxy does not
  decrypt or authenticate anything; it relays.
- Raw `request_line` is sanitized (control bytes stripped) before parsing.

## Limitations
- Absolute-form URLs only for plain HTTP (`GET http://host/path …`); origin-form
  with a `Host` header works too.
- A single origin connection per proxied request (`Connection: close`); no
  keep-alive pooling yet.
- No authorization (proxy-auth), no HTTPS interception, no retrying.

## Version
0.1.0