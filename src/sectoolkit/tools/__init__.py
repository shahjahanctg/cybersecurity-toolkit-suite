"""Tool implementations grouped by delivery wave."""

from __future__ import annotations

from ..core.registry import ToolRegistry


def load_registry() -> ToolRegistry:
    """Build the full tool registry (lazy to keep imports fast)."""
    from . import defense, extras, forensics, malware, network, proxy, redteam, vulnscan

    registry = ToolRegistry()
    for pkg in (network, defense, proxy, vulnscan, forensics, malware, redteam, extras):
        pkg.register(registry)
    return registry