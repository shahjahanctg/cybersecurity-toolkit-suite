# subnet-calc — Subnet / VLSM Calculator (W1)

Compute network facts for a CIDR block, or produce a Variable Length Subnet
Mask (VLSM) allocation plan from a list of required host counts.

## What it does NOT do
- Does not touch the network. Pure offline computation.
- Does not allocate real addresses or modify any device.

## Authorized use
No authorization is needed — this is arithmetic. Still used for planning any
authorized network.

## Usage
```bash
sec-toolkit subnet-calc --cidr 192.168.1.0/24
sec-toolkit subnet-calc --cidr 10.0.0.0/22 --mode vlsm --hosts 100,50,25,12 --json
```

## Output
CIDR facts: network, netmask, wildcard, broadcast, host counts, first/last
usable host. VLSM mode adds per-subnet allocations
(`subnet-N <cidr> hosts <count>` with usable-host limits). JSON via `--json`.

## Safety notes
None. Cannot be misused operationally.

## Limitations
- IPv4 only.
- VLSM blocks must fit inside the supernet (overflow → error).
- Host counts are integers ≥ 1; network+broadcast are added automatically.

## Version
0.1.0