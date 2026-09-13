"""Global application configuration (JSON), with per-tool overrides."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict

DEFAULT_CONFIG: Dict[str, Any] = {
    "log_level": "INFO",
    "output_dir": ".",
    "theme": "dark",
    "timeout_seconds": 5,
    "max_threads": 256,
    "scan_speed": "normal",            # slow | normal | fast
    "user_agent": "SecurityToolkitSuite/0.1.0",
    "proxy": {"host": "", "port": 0, "type": ""},
    "paths": {
        "wordlists": "data/wordlists",
        "yara_rules": "data/yara",
        "volatility_profiles": "",
    },
    "tool_defaults": {},
}


@dataclass
class AppConfig:
    root: Path = field(default_factory=lambda: Path(".").resolve())
    data: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.data = dict(DEFAULT_CONFIG)
        for key, value in DEFAULT_CONFIG["paths"].items():
            if value:
                p = self.root / value
                self.data["paths"][key] = str(p)

    @classmethod
    def load(cls, root: Path, config_path: Path | None = None) -> "AppConfig":
        cfg = cls(root=root)
        if config_path and config_path.exists():
            raw = json.loads(config_path.read_text(encoding="utf-8"))
            cfg.data = _deep_merge(DEFAULT_CONFIG, raw)
            cfg.data["paths"] = {
                k: str((config_path.parent / v).resolve()) if v and not Path(str(v)).is_absolute() else v
                for k, v in cfg.data.get("paths", {}).items()
            }
        # Absolute-ize root-relative paths that were left default
        base = cfg.data["paths"]
        for key, value in list(base.items()):
            if value and not Path(str(value)).is_absolute() and key not in ():
                base[key] = str((root / value).resolve())
        return cfg

    def save(self, config_path: Path) -> None:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8")

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def tool_default(self, tool_name: str, key: str, default: Any = None) -> Any:
        td = self.data.get("tool_defaults", {}).get(tool_name, {})
        return td.get(key, default)


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out