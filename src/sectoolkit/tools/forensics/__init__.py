"""Wave 5 (forensics) tools. Registered during the W5 delivery wave."""

from __future__ import annotations

from ...core.registry import ToolRegistry


def register(registry: ToolRegistry) -> int:
    from . import (disk_image, memory_forensics, deleted_recovery,
                   browser_artifacts, android_forensics)

    count = 0
    for mod in (disk_image, memory_forensics, deleted_recovery,
                browser_artifacts, android_forensics):
        registry.register(mod)
        count += 1
    return count