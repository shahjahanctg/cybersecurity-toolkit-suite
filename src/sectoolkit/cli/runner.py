"""CLI runner: turns the tool registry into argparse subcommands."""

from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import sectoolkit
from ..core.config import AppConfig
from ..core.logging_setup import setup_logging
from ..core.tool import (ToolContext, author_banner, redact_params,
                         requires_authorization, safety_check)
from ..tools import load_registry


class Cancellation:
    """Shared cooperative stop flag (set by SIGINT or GUI cancel)."""

    def __init__(self) -> None:
        self.event = threading.Event()

    def is_set(self) -> bool:
        return self.event.is_set()


def build_parser(registry=None) -> argparse.ArgumentParser:
    registry = registry or load_registry()
    parser = argparse.ArgumentParser(
        prog="sec-toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Security Toolkit Suite — authorized-use-only cybersecurity tools.\n\n"
            "Run tools ONLY against systems you own or hold explicit written\n"
            "authorization to test. Unauthorized scanning is illegal in most\n"
            "jurisdictions.\n\n"
            "Global flags may appear before or after the tool subcommand."
        ),
        epilog="Try: sec-toolkit list\n"
               "     sec-toolkit subnet-calc --cidr 192.168.1.0/24 --json\n"
               "     sec-toolkit port-scan --host scanme.example.org --ports 80,443",
    )
    parser.add_argument("--version", action="version",
                        version=f"sec-toolkit {sectoolkit.__version__}")
    parser.add_argument("--config", type=Path, default=None,
                        help="Path to a JSON config file")
    parser.add_argument("--output-dir", type=Path, default=None,
                        help="Directory for generated artifacts")
    parser.add_argument("--log-level", default=None,
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Log verbosity (default from config)")
    parser.add_argument("--json", action="store_true",
                        help="Emit structured JSON instead of human-readable text")
    parser.add_argument("--yes", action="store_true",
                        help="Skip interactive confirmations (CI/automation only)")

    sub = parser.add_subparsers(dest="tool", metavar="TOOL")
    sub.add_parser(
        "list",
        help="List all available tools grouped by wave",
        description="List all available tools grouped by wave.",
    )
    _add_tool_subcommands(sub, registry)
    return parser


def _add_tool_subcommands(sub, registry) -> None:
    for meta in registry.all_meta():
        p = sub.add_parser(
            meta.name,
            help=meta.title,
            description=f"{meta.title}\n\n{meta.description}",
        )
        p.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
        p.add_argument("--yes", action="store_true", help=argparse.SUPPRESS)
        for field in meta.fields:
            prefix, spec = field.to_cli_arg()
            p.add_argument(prefix, **spec)


def _run_tool(reg, name, args, cfg, cancel, json_out, log_level) -> int:
    module = reg.get(name)
    if module is None:
        print(f"unknown tool: {name}. Try 'sec-toolkit list'.", file=sys.stderr)
        return 2

    meta = module.TOOL
    logger = setup_logging(level=log_level or cfg.get("log_level", "INFO"))

    params = {}
    for field in meta.fields:
        raw = getattr(args, field.name, None)
        if raw is None:
            raw = field.default
        params[field.name] = field.coerce(raw)

    output_dir = (args.output_dir or Path(cfg.get("output_dir", "."))).resolve()
    ctx = ToolContext(
        config=cfg,
        logger=logger,
        output_dir=output_dir,
        interactive=not args.yes,
        extra={"stop_event": cancel.event},
    )

    if requires_authorization(meta):
        if not args.yes:
            print(author_banner(meta), file=sys.stderr)
        else:
            logger.warning("running with confirmations suppressed; ensure authorization")

    targets = [str(params.get(f) or "") for f in meta.target_fields]
    warnings = safety_check(meta, ctx, targets)
    for w in warnings:
        logger.warning(w)
        print(f"(!) {w}", file=sys.stderr)

    start = datetime.now(timezone.utc)
    try:
        result = module.run(params, ctx)
    except PermissionError as exc:
        print(f"denied: {exc}", file=sys.stderr)
        logger.error("run refused: %s", exc)
        return 3
    except ValueError as exc:
        print(f"invalid input: {exc}", file=sys.stderr)
        logger.error("invalid input: %s", exc)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted by user.", file=sys.stderr)
        return 130
    elapsed = datetime.now(timezone.utc) - start

    envelope = {
        "suite": "sec-toolkit",
        "suite_version": sectoolkit.__version__,
        "tool": meta.name,
        "tool_version": meta.version,
        "wave": meta.wave,
        "ran_at": start.isoformat(),
        "elapsed_ms": int(elapsed.total_seconds() * 1000),
        "params": redact_params(params),
        "warnings": warnings,
        "result": result,
    }

    if json_out:
        print(json.dumps(envelope, indent=2, ensure_ascii=False, default=str))
        return 0

    try:
        renderer = getattr(module, "render", None)
        text = renderer(result) if callable(renderer) else json.dumps(result, indent=2, default=str)
    except Exception as exc:  # rendering must never crash the run
        text = json.dumps(result, indent=2, default=str)
        logger.warning("human renderer failed (%s); showing JSON", exc)
    print(text)
    return 0


def _cmd_list(registry, args) -> int:
    from sectoolkit import WAVES
    waves = registry.waves()
    lines = []
    for wave_no in sorted(waves):
        title, prio = WAVES[wave_no]
        lines.append(f"{title}  (priority {prio})")
        for meta in waves[wave_no]:
            flags = []
            if meta.privileges != "none":
                flags.append(meta.privileges)
            tag = f"  [{', '.join(flags)}]" if flags else ""
            lines.append(f"  {meta.name:20s} {meta.title}{tag}")
        lines.append("")
    print("\n".join(lines))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    registry = load_registry()
    parser = build_parser(registry)
    args = parser.parse_args(argv)

    cancel = Cancellation()
    signal.signal(signal.SIGINT, lambda *_: cancel.event.set())

    if not args.tool or args.tool == "list":
        if args.tool == "list":
            return _cmd_list(registry, args)
        parser.print_help()
        return 0

    cfg = AppConfig.load(Path.cwd(), args.config)
    json_out = args.json or getattr(args, "json", False)
    log_level = args.log_level or cfg.get("log_level", "INFO")
    return _run_tool(registry, args.tool, args, cfg, cancel, json_out, log_level)


if __name__ == "__main__":
    raise SystemExit(main())