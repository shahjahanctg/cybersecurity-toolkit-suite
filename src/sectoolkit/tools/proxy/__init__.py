"""Wave 3 — Proxy & Tunnel tools."""

from __future__ import annotations

from ...core.registry import ToolRegistry


def register(registry: ToolRegistry) -> int:
    from . import http_proxy, port_forward, socks5_proxy, wireguard_vpn

    count = 0
    for mod in (http_proxy, port_forward, socks5_proxy, wireguard_vpn):
        registry.register(mod)
        count += 1
    return count