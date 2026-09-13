"""Tool abstraction: metadata, field specs, execution context, safety gates."""

from __future__ import annotations

import argparse
import copy
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .config import AppConfig
from .privileges import do_have_raw_sockets

# Field types rendered by the generic GUI form and parsed by the CLI.
FIELD_TYPES = (
    "text", "int", "int_range", "bool", "combo", "file", "dir",
    "textarea", "secret", "cidr", "ports", "host",
)


@dataclass
class FieldSpec:
    name: str
    label: str
    type: str = "text"
    required: bool = False
    default: Any = None
    help: str = ""
    options: List[str] = field(default_factory=list)
    placeholder: str = ""

    def __post_init__(self) -> None:
        if self.type not in FIELD_TYPES:
            raise ValueError(f"unknown field type {self.type!r}")

    def to_cli_arg(self) -> dict:
        """Return an argparse argument spec derived from the field spec."""
        prefix = "--" + self.name.replace("_", "-")
        spec: dict = {
            "dest": self.name,
            "help": (self.help + (" (required)" if self.required else "")),
        }
        if self.type == "bool":
            spec["action"] = argparse.BooleanOptionalAction
            spec["default"] = self.default
        elif self.type == "int":
            spec["type"] = int
            spec["default"] = self.default
        elif self.type == "int_range":
            spec["type"] = int
            spec["default"] = self.default
        elif self.type == "combo":
            spec["choices"] = self.options
            spec["default"] = self.default
        elif self.type in ("file", "dir"):
            spec["type"] = Path
            spec["default"] = self.default
        else:
            spec["default"] = self.default
        if self.required:
            spec["required"] = True
        return (prefix, spec)

    def coerce(self, raw: Any) -> Any:
        """Coerce a raw value (from CLI or GUI) into the typed value."""
        if raw is None or raw == "":
            return self.default
        try:
            if self.type == "int":
                return int(raw)
            if self.type == "int_range":
                lo, _, hi = str(raw).partition("-")
                lo_i, hi_i = int(lo or 0), int(hi or 0)
                if not hi or lo_i <= hi_i:
                    return (lo_i, hi_i)
                return (hi_i, lo_i)
            if self.type == "bool":
                if isinstance(raw, bool):
                    return raw
                return str(raw).strip().lower() in ("1", "true", "yes", "on")
            if self.type in ("file", "dir"):
                return Path(str(raw))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid value for {self.name!r}: {raw!r}") from exc
        return raw


@dataclass
class ToolMeta:
    name: str                      # CLI/subcommand name, e.g. "subnet-calc"
    title: str                     # human title
    wave: int
    description: str
    category: str                  # network | defense | proxy | vulnscan | forensics | malware | redteam | extras
    mode: str = "read"             # read | act
    privileges: str = "none"       # none | net_raw | root | admin
    destructive: bool = False
    target_fields: List[str] = field(
        default_factory=lambda: ["host", "subnet", "domain", "target"])
    fields: List[FieldSpec] = field(default_factory=list)
    version: str = "0.1.0"


@dataclass
class ToolContext:
    """Execution context passed to every tool's run()."""
    config: AppConfig
    logger: logging.Logger
    output_dir: Path
    interactive: bool = True
    extra: Dict[str, Any] = field(default_factory=dict)

    def ensure_output_dir(self) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        return self.output_dir


def requires_authorization(meta: ToolMeta) -> bool:
    """Whether a tool should show the authorized-use banner up front.

    Destructive tools and network-touching tools (recon/proxy/web-attack
    categories) get the reminder; pure local/computation tools do not.
    """
    if meta.destructive:
        return True
    return meta.category in ("network", "vulnscan", "proxy", "redteam")


def safety_check(meta: ToolMeta, ctx: ToolContext, targets: List[str]) -> List[str]:
    """Surface capability warnings before a run. Returns warnings list.

    Raw-socket tools explain the capability they need; read-only fallbacks
    are called out so the operator knows what they are signing up for.
    """
    warnings: List[str] = []
    if meta.privileges in ("net_raw", "root") and meta.mode == "act":
        ok, detail = do_have_raw_sockets()
        if not ok:
            warnings.append(
                f"{meta.name} needs raw socket capability (CAP_NET_RAW / "
                f"root on Linux, admin on Windows) for its active scan mode. "
                f"Detected: {detail}. Active mode will fail fast; read-only "
                "mode may still work."
            )
    return warnings


def redact_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of params with secret values scrubbed."""
    scrubbed = copy.deepcopy(params)
    for key, value in scrubbed.items():
        if isinstance(value, str) and key.lower() in (
            "password", "pass", "secret", "key", "token", "authorization", "capture_filter_secret",
        ):
            scrubbed[key] = "***REDACTED***"
    return scrubbed


def author_banner(meta: ToolMeta) -> str:
    """Authorization warning banner shown for destructive / network tools."""
    lines = [
        "=" * 72,
        f"AUTHORIZED-USE WARNING — {meta.title}",
        "=" * 72,
        "This tool is provided for use ONLY against systems you own or for",
        "which you hold explicit written authorization to test.",
        "Unauthorized scanning or testing may be a criminal offense in your",
        "jurisdiction. You are responsible for your own actions.",
    ]
    if meta.destructive:
        lines.append(
            "This tool can change system state. Only run it in an isolated lab "
            "with a recovery plan."
        )
    lines.append("=" * 72)
    return "\n".join(lines)


RunFn = Callable[[Dict[str, Any], ToolContext], Dict[str, Any]]