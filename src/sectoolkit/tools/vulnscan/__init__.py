"""Wave 4 (vulnscan) tools. Registered during the W4 delivery wave."""

from __future__ import annotations

from ...core.registry import ToolRegistry


def register(registry: ToolRegistry) -> int:
    from . import vuln_scanner, web_fuzzer, sqli_detector, password_auditor

    count = 0
    for mod in (vuln_scanner, web_fuzzer, sqli_detector, password_auditor):
        registry.register(mod)
        count += 1
    return count