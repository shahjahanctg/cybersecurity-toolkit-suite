# port-forward — Port Forwarder (TCP/UDP relay) (W3)

Bidirectional TCP or UDP port relay in `forward` or `reverse` orientation,
streaming bytes between a listen socket and a target `host:port`.

## What it does NOT do
- Does NOT encrypt or tunnel through firewalls; it is a plain socket relay.
- Does NOT reach the internet on your behalf or scan anything — it waits for
  inbound connections and relays them.
- `reverse` is an orientation label only (the relay side that exposes the "vulnerable
  service" forwards to your collector); the mechanism is identical.

## Authorized use
Port relays are standard tooling for pivoting during an authorized test and
for service testing. Because it relays connections to whatever target you name,
using it against systems you do not own is unauthorized access — use it only
with written authorization for authorized targets.

## Prerequisites
None (pure standard library). Choose an unused listen port.

## Usage
```bash
# forward a local TCP port to an internal service
sec-toolkit port-forward --mode forward --proto tcp --listen-port 9090 \
  --target-host 127.0.0.1 --target-port 5432 --duration 600

# UDP relay, reverse orientation (exposed side -> your collector)
sec-toolkit port-forward --mode reverse --proto udp --listen-port 5150 \
  --target-host 127.0.0.1 --target-port 9999

# run until cancelled
sec-toolkit port-forward --proto tcp --listen-port 9090 --target-port 80 --duration 0
```

## Output
`{listen, target, orientation, protocol, connections, bytes_to_target,
bytes_to_client, sessions[]}`. TCP sessions list `client -> target` (bounded to
100 most recent). UDP reports an approximate session count and byte totals.

## Safety notes
- An authorized-use banner is shown before relaying; only relay to targets
  you are authorized to reach.
- Bounded TCP connection log; sockets are closed in `finally`; duration or the
  stop event (Ctrl-C / GUI Cancel) ends the relay cleanly (accept loop polls at
  0.5s).

## Limitations
- Single target per run; multi-rule setups mean multiple runs.
- No protocol awareness, inspection, or modification — it is a pure stream/packet
  relay.
- UDP client mapping is best-effort (replies are sent to the most recently active
  client).

## Version
0.1.0