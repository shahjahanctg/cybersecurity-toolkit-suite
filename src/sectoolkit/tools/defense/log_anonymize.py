"""Log Anonymizer — W2 Defense & Monitoring.

Reads a log/text file and writes an anonymized copy, redacting IPv4/IPv6
addresses, email addresses, and MAC addresses using either stable placeholders
([IP:1], [EMAIL:2]) or hash tokens (sha256-derived) so the same value maps to
the same replacement within one run. The original file is never modified.

Placeholder/hash values are NOT reversible — treat the output as de-identified
with caution (low-entropy values such as common IPs can be re-identified).
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Callable, Dict, List, Tuple

from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="log-anonymize",
    title="Log Anonymizer",
    wave=2,
    description=(
        "Produce an anonymized copy of a log file, replacing IP/email/MAC "
        "addresses (and optional custom patterns) with stable placeholders or "
        "hash tokens. The original file is never modified."
    ),
    category="defense",
    mode="act",
    privileges="none",
    fields=[
        FieldSpec(name="input", label="Input log file", type="file", required=True,
                  help="Log or text file to anonymize (original is untouched)"),
        FieldSpec(name="output", label="Output file", type="text", default="",
                  placeholder="(auto: <input>-anon.<ext>)",
                  help="Destination path; empty = derive from input name"),
        FieldSpec(name="redact_ips", label="Redact IP addresses", type="bool", default=True,
                  help="IPv4 + basic IPv6"),
        FieldSpec(name="redact_emails", label="Redact email addresses", type="bool", default=True,
                  help="Standard email pattern"),
        FieldSpec(name="redact_macs", label="Redact MAC addresses", type="bool", default=True,
                  help="Colon/hyphen separated MACs"),
        FieldSpec(name="mode", label="Replacement", type="combo",
                  options=["placeholder", "hash"], default="placeholder",
                  help="placeholder: [IP:1] style; hash: sha256 prefix tokens"),
        FieldSpec(name="custom_patterns", label="Custom regex patterns", type="textarea",
                  default="",
                  help="One regex per line; matches replaced with [CUSTOM:n]"),
    ],
)


def _sha_token(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]


def _build_redactors(params: dict) -> List[Tuple[str, str, Callable[[str], str]]]:
    """Return list of (category, pattern, replacer)."""
    mode = params.get("mode", "placeholder")
    counters: Dict[str, int] = {}
    mapping: Dict[Tuple[str, str], str] = {}

    def factory(category: str):
        def replace(value: str, category=category) -> str:
            key = (category, value)
            if key in mapping:
                return mapping[key]
            counters[category] = counters.get(category, 0) + 1
            if mode == "hash":
                token = _sha_token(f"{category}:{value}")
            else:
                token = f"[{category.upper()}:{counters[category]}]"
            mapping[key] = token
            return token
        return replace

    patterns: List[Tuple[str, str, Callable[[str], str]]] = []
    if params.get("redact_ips", True):
        patterns.append(("ip",
                         r"\b(?:\d{1,3}\.){3}\d{1,3}\b", factory("ip")))
        # Practical IPv6: full 8-group form, compressed :: forms, and
        # v4-mapped. Requires a literal "::" or 8 hextets so clock-style
        # 10:00:00 and MAC addresses are not mistaken for addresses.
        ipv6_full = r"[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7}"
        ipv6_compressed = (
            r"(?:"
            r"(?:[0-9a-fA-F]{1,4}:){1,7}::"
            r"|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{0,4}"
            r"|[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}"
            r")")
        ipv6_mapped = r"::ffff:\d{1,3}(?:\.\d{1,3}){3}"
        patterns.append(("ip",
                         rf"\b(?:(?:{ipv6_full})|(?:{ipv6_compressed})|"
                         rf"(?:{ipv6_mapped}))\b",
                         factory("ip")))
    if params.get("redact_emails", True):
        patterns.append(("email",
                         r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
                         factory("email")))
    if params.get("redact_macs", True):
        patterns.append(("mac",
                         r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b",
                         factory("mac")))
    custom = str(params.get("custom_patterns") or "")
    for line in custom.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            re.compile(line)
        except re.error as exc:
            raise ValueError(f"invalid custom regex {line!r}: {exc}") from exc
        patterns.append(("custom", line, factory("custom")))
    return patterns


def anonymize(text: str, params: dict) -> tuple:
    """Apply all enabled redactors to text. Returns (text, counts)."""
    patterns = _build_redactors(params)
    counts: Dict[str, int] = {}
    out = text

    # Apply IPv4 before IPv6 so the literal 127.0.0.1 form does not confuse
    # the generic scanner; order is otherwise not significant.
    for category, pattern, replacer in patterns:
        new_out, n = re.subn(pattern, lambda m: replacer(m.group(0)), out)
        counts.setdefault(category, 0)
        # Counting is per-pattern; merge same-category occurrences.
        if n:
            counts[category] += n
        out = new_out
    # Emails can embed dots that also match the IPv4 pattern? No: IPv4 requires
    # digits. No conflict beyond ordering.
    return out, counts


def run(params: dict, ctx: ToolContext) -> dict:
    input_path_raw = str(params.get("input") or "").strip()
    if not input_path_raw:
        raise ValueError("an input log file is required")
    input_path = Path(input_path_raw).expanduser()
    if not input_path.is_file():
        raise ValueError(f"input file not found: {input_path}")

    size = input_path.stat().st_size
    if size > 200 * 1024 * 1024:
        raise ValueError("input larger than 200 MB — refusing (limited tool)")

    with input_path.open("rb") as fh:
        head = fh.read(8192)
    if b"\x00" in head:
        raise ValueError("input looks binary — refusing non-text file")

    with input_path.open("r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()

    out_text, counts = anonymize(text, params)

    output_raw = str(params.get("output") or "").strip()
    if not output_raw:
        output_path = input_path.with_name(
            f"{input_path.stem}-anon{input_path.suffix}")
    else:
        output_path = Path(output_raw).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(out_text, encoding="utf-8")

    return {
        "input": str(input_path),
        "input_size_chars": len(text),
        "output": str(output_path),
        "output_size_chars": len(out_text),
        "mode": params.get("mode", "placeholder"),
        "redactions": counts,
        "total_redactions": sum(counts.values()),
    }


def render(result: dict) -> str:
    lines = [
        f"Anonymized {result['input']} -> {result['output']}",
        f"  input:  {result['input_size_chars']} chars",
        f"  output: {result['output_size_chars']} chars",
        f"  mode:   {result['mode']}",
        f"  redactions: {result['total_redactions']}",
    ]
    for category, n in sorted(result["redactions"].items()):
        lines.append(f"    {category:<8} {n}")
    lines.append("")
    lines.append("NOTE: placeholders/hashes are deterministic per run but not "
                 "reversible; low-entropy values may still be re-identifiable.")
    return "\n".join(lines)