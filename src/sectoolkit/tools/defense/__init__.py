"""Wave 2 — Defense & Monitoring tools."""

from __future__ import annotations

from ...core.registry import ToolRegistry


def register(registry: ToolRegistry) -> int:
    from . import firewall_audit, hids_agent, honeypot, log_anonymize

    count = 0
    for mod in (firewall_audit, hids_agent, honeypot, log_anonymize):
        registry.register(mod)
        count += 1
    return count