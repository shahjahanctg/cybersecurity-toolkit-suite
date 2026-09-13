"""Subnet / VLSM Calculator — W1 Network Recon.

Pure-computation tool (no privileges). Calculates network facts for a CIDR
block and, in VLSM mode, produces a largest-first Variable Length Subnet Mask
allocation plan for a set of required host counts.
"""

from __future__ import annotations

from ...core.netutil import cidr_to_network, network_info, vlsm_plan
from ...core.output import key_value
from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="subnet-calc",
    title="Subnet / VLSM Calculator",
    wave=1,
    description=(
        "Compute network/broadcast/usable-host facts for a CIDR block, or "
        "produce a Variable Length Subnet Mask (VLSM) allocation plan from a "
        "set of required host counts. Pure math — runs offline, no privileges."
    ),
    category="network",
    mode="read",
    privileges="none",
    fields=[
        FieldSpec(name="mode", label="Mode", type="combo", default="subnet",
                  options=["subnet", "vlsm"],
                  help="subnet: basic CIDR facts; vlsm: allocation plan"),
        FieldSpec(name="cidr", label="Network (CIDR)", type="text", required=True,
                  placeholder="192.168.1.0/24",
                  help="Base network in CIDR form, e.g. 192.168.1.0/24"),
        FieldSpec(name="hosts", label="Required host counts (VLSM)", type="text",
                  default="50,20,10",
                  help="Comma-separated host counts for VLSM mode, e.g. 50,20,10"),
    ],
)

def run(params: dict, ctx: ToolContext) -> dict:
    mode = params.get("mode", "subnet")
    cidr = str(params.get("cidr", "")).strip()
    if not cidr:
        raise ValueError("a network (CIDR) is required")

    if mode == "vlsm":
        hosts_raw = str(params.get("hosts") or "").strip()
        if not hosts_raw:
            raise ValueError("VLSM mode requires comma-separated host counts")
        try:
            host_counts = [int(h.strip()) for h in hosts_raw.split(",")]
        except ValueError as exc:
            raise ValueError(
                f"host counts must be integers: {hosts_raw!r}") from exc
        plan = vlsm_plan(cidr, host_counts)
        return {"mode": "vlsm", "supernet_cidr": plan["supernet_cidr"], **plan}

    net = cidr_to_network(cidr)
    return {"mode": "subnet", **network_info(net)}


def render(result: dict) -> str:
    if result.get("mode") == "vlsm":
        lines = [
            f"VLSM plan for {result['supernet_cidr']}",
            f"  requested hosts: {', '.join(map(str, result['planned']))}",
            f"  total block size needed: {result['total_block_size']}",
            "",
        ]
        for sub in result["subnets"]:
            lines.append(
                f"  {sub['name']:11s} {sub['cidr']:18s} "
                f"hosts {sub['requested_hosts']:>4d} "
                f"(usable {sub['usable_hosts']:>4d}) "
                f"first {sub['first_host']} last {sub['last_host']}"
            )
        return "\n".join(lines)

    rows = [
        ("Network address", result["network"]),
        ("Prefix", f"/{result['cidr']}"),
        ("Netmask", result["netmask"]),
        ("Wildcard", result["wildcard"]),
        ("Broadcast", result["broadcast"]),
        ("Total addresses", result["num_addresses"]),
        ("Usable hosts", result["num_usable_hosts"]),
        ("First host", result["first_host"]),
        ("Last host", result["last_host"]),
        ("Private range", result["is_private"]),
        ("Loopback", result["is_loopback"]),
    ]
    return key_value(rows)