"""Wave 7 (redteam) tools. Registered during the W7 delivery wave."""

from __future__ import annotations

from ...core.registry import ToolRegistry


def register(registry: ToolRegistry) -> int:
    from . import (privesc_enum, buffer_overflow, metasploit_module,
                   c2_obfuscation, c2_jitter, persistence_rules)

    count = 0
    for mod in (privesc_enum, buffer_overflow, metasploit_module,
                c2_obfuscation, c2_jitter, persistence_rules):
        registry.register(mod)
        count += 1
    return count