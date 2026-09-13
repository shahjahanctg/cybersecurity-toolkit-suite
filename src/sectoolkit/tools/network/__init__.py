"""Wave 1 — Network Recon tools."""

from __future__ import annotations

import pkgutil
import importlib

from ...core.registry import ToolRegistry


def register(registry: ToolRegistry) -> int:
    """Register all implemented network tools into the global registry."""
    from . import subnet_calc, arp_scanner, port_scanner, dns_resolver, packet_sniffer

    for mod in (subnet_calc, arp_scanner, port_scanner, dns_resolver, packet_sniffer):
        registry.register(mod)
    return 5