"""Shared networking helpers: CIDR math, VLSM planning, port parsing, host checks."""

from __future__ import annotations

import ipaddress
import re
from typing import List

MAX_HOST_EXPANSION = 4096


def parse_ip(text: str) -> ipaddress.IPv4Address:
    """Parse a dotted-quad IPv4 address, raising ValueError on bad input."""
    try:
        return ipaddress.IPv4Address(text.strip())
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"invalid IPv4 address: {text!r}") from exc


def cidr_to_network(text: str) -> ipaddress.IPv4Network:
    """Parse 'a.b.c.d/prefix' (prefix optional -> /32 netmask default)."""
    text = text.strip()
    if "/" not in text:
        text = text + "/32"
    try:
        return ipaddress.IPv4Network(text, strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
        raise ValueError(f"invalid CIDR/network: {text!r}") from exc


def network_info(net: ipaddress.IPv4Network) -> dict:
    """Return a JSON-able description of a network."""
    hosts = list(net.hosts())
    return {
        "network": str(net.network_address),
        "cidr": int(net.prefixlen),
        "netmask": str(net.netmask),
        "wildcard": str(net.hostmask),
        "broadcast": str(net.broadcast_address) if net.prefixlen < 31 else None,
        "num_addresses": net.num_addresses,
        "num_usable_hosts": len(hosts),
        "first_host": str(hosts[0]) if hosts else None,
        "last_host": str(hosts[-1]) if hosts else None,
        "is_private": net.is_private,
        "is_loopback": net.is_loopback,
    }


def expand_hosts(cidr: str) -> List[str]:
    """Expand a CIDR to usable host addresses, bounded by MAX_HOST_EXPANSION."""
    net = cidr_to_network(cidr)
    if net.num_addresses > MAX_HOST_EXPANSION:
        raise ValueError(
            f"refusing to expand {cidr} ({net.num_addresses} addresses); "
            f"limit is {MAX_HOST_EXPANSION}")
    return [str(h) for h in net.hosts()]


def _prefix_for(needed: int) -> int:
    """Smallest prefix p (<=30) such that 2**(32-p) >= needed."""
    if needed < 1:
        raise ValueError("needed must be >= 1")
    p = 32
    while p > 0 and (1 << (32 - p)) < needed:
        p -= 1
    return max(min(p, 30), 0)


def vlsm_plan(cidr: str, host_counts: List[int]) -> dict:
    """Create a VLSM (Variable Length Subnet Mask) allocation plan.

    Hosts are allocated largest-first from the given network. Each requested
    host count is treated as usable hosts; network + broadcast (2) are added
    to find the required block size. Returns a JSON-able dict.
    """
    net = cidr_to_network(cidr)
    requested = sorted(int(h) for h in host_counts)
    if any(h < 1 for h in requested):
        raise ValueError("host counts must be >= 1")
    if not requested:
        raise ValueError("at least one host count is required")

    plan = []
    cursor = net.network_address
    total_block_size = 0
    for i, hosts in enumerate(sorted(requested, reverse=True), start=1):
        prefix = _prefix_for(hosts + 2)
        size = 1 << (32 - prefix)
        subnet = ipaddress.IPv4Network((cursor, prefix), strict=False)
        if not subnet.subnet_of(net):
            raise ValueError(
                f"VLSM plan exceeds supernet {cidr} at request #{i} "
                f"({hosts} hosts)")
        usable = list(subnet.hosts())
        plan.append({
            "index": i,
            "name": f"subnet-{i}",
            "cidr": str(subnet),
            "prefix": prefix,
            "network": str(subnet.network_address),
            "broadcast": str(subnet.broadcast_address),
            "size": size,
            "requested_hosts": hosts,
            "usable_hosts": len(usable),
            "first_host": str(usable[0]) if usable else None,
            "last_host": str(usable[-1]) if usable else None,
        })
        cursor += size
        total_block_size += size

    return {
        "supernet_cidr": str(net),
        "planned": sorted(requested, reverse=True),
        "total_requested_hosts": sum(requested),
        "total_block_size": total_block_size,
        "subnets": plan,
    }


def parse_port_spec(spec: str) -> List[int]:
    """Parse '80', '80,443', '1-100', or a mix. Returns sorted unique ports."""
    spec = spec.strip()
    if not spec:
        raise ValueError("empty port list")
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
        if not m:
            raise ValueError(f"invalid port token: {part!r}")
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        if lo < 1 or hi > 65535 or lo > hi:
            raise ValueError(f"port range out of bounds: {part!r}")
        ports.update(range(lo, hi + 1))
    return sorted(ports)


def resolve_literal_host(host: str) -> str:
    """Validate a host, hostname, or IP literal. Returns the host string."""
    host = host.strip()
    if not host:
        raise ValueError("empty host")
    allowed = re.compile(r"^[A-Za-z0-9.\-_:\[\]]+$")
    if not allowed.match(host):
        raise ValueError(f"invalid host value: {host!r}")
    return host


def is_loopback(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host.split("/")[0])
    except ValueError:
        return host.strip().lower() in ("localhost", "::1", "127.0.0.1")
    return ip.is_loopback


def is_private(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host.split("/")[0])
    except ValueError:
        return False
    return ip.is_private


def is_lab_target(host: str) -> bool:
    """A target is 'lab' if it is loopback or localhost."""
    return is_loopback(host)