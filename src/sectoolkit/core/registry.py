"""In-memory registry of all tools in the suite (single source of truth)."""

from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass
from typing import Dict, List, Optional, Protocol

from .tool import ToolMeta


class ToolModule(Protocol):
    TOOL: ToolMeta

    def run(self, params: dict, ctx) -> dict: ...


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: Dict[str, ToolModule] = {}

    def register(self, module: ToolModule) -> None:
        meta = module.TOOL
        if meta.name in self._tools:
            raise ValueError(f"duplicate tool name {meta.name!r}")
        self._tools[meta.name] = module

    def register_package(self, package_name: str, package_obj) -> int:
        """Register every module inside a wave package that defines TOOL."""
        count = 0
        for modinfo in pkgutil.iter_modules(package_obj.__path__):
            mod = importlib.import_module(f"{package_name}.{modinfo.name}")
            if hasattr(mod, "TOOL"):
                self.register(mod)
                count += 1
        return count

    def get(self, name: str) -> Optional[ToolModule]:
        return self._tools.get(name)

    def names(self) -> List[str]:
        return sorted(self._tools.keys())

    def all_meta(self) -> List[ToolMeta]:
        return sorted((m.TOOL for m in self._tools.values()),
                      key=lambda t: (t.wave, t.title))

    def by_wave(self, wave: int) -> List[ToolMeta]:
        return [m for m in self.all_meta() if m.wave == wave]

    def waves(self) -> Dict[int, List[ToolMeta]]:
        out: Dict[int, List[ToolMeta]] = {}
        for meta in self.all_meta():
            out.setdefault(meta.wave, []).append(meta)
        return out

    def __len__(self) -> int:
        return len(self._tools)