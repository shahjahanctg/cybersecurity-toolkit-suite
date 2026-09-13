"""Wave 8 (extras) tools. Registered during the W8 delivery wave."""

from __future__ import annotations

from ...core.registry import ToolRegistry


def register(registry: ToolRegistry) -> int:
    from . import burp_extension, wireless_wpa_audit

    count = 0
    for mod in (burp_extension, wireless_wpa_audit):
        registry.register(mod)
        count += 1
    return count