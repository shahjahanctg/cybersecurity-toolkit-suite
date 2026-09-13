"""Output formatting: structured (JSON) + human-readable rendering."""

from __future__ import annotations

import json
from typing import Any, Dict


def to_json(data: Dict[str, Any], indent: int = 2) -> str:
    return json.dumps(data, indent=indent, ensure_ascii=False, default=str)


def render_table(headers: list[str], rows: list[list[Any]]) -> str:
    """Render a simple aligned text table."""
    if not headers:
        return ""
    full = [headers] + [[str(c) for c in r] for r in rows]
    widths = [max(len(row[i]) for row in full) for i in range(len(headers))]
    lines = []
    for ridx, row in enumerate(full):
        line = "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip()
        lines.append(line)
        if ridx == 0:
            lines.append("  ".join("-" * w for w in widths))
    return "\n".join(lines)


def key_value(rows: list[tuple[str, Any]], indent: int = 0) -> str:
    pad = " " * indent
    out = []
    for key, value in rows:
        if isinstance(value, (dict, list)):
            out.append(f"{pad}{key}:")
            out.append(json.dumps(value, indent=2, default=str, ensure_ascii=False))
        else:
            out.append(f"{pad}{key}: {value}")
    return "\n".join(out)


def flatten_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten a result dict for table display (nested dicts converted to text)."""
    flat: Dict[str, Any] = {}
    for key, value in result.items():
        if isinstance(value, (dict, list)):
            flat[key] = json.dumps(value, default=str, ensure_ascii=False)
        else:
            flat[key] = value
    return flat