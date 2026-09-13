"""C2 Traffic Obfuscation Demo — W7 Red Team / C2.

Demonstrates network-traffic-shaping techniques C2 agents use to look
innocuous: XOR, base64, combined XOR+base64, HTTP-like wrapper framing,
and random padding. Takes your marker text/config, writes the obfuscated
form plus a matching deobfuscator snippet, and shows size/entropy stats.

Read-only + local codegen. The demo material never leaves the machine.
"""

from __future__ import annotations

import base64
import datetime as _dt
import importlib
import random
import string
from pathlib import Path
from typing import Dict, List

from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="c2-obfuscation",
    title="C2 Traffic Obfuscation Demo",
    wave=7,
    description=(
        "Demonstrate C2 traffic-shaping ideas on your own marker text: "
        "XOR / base64 / HTTP-like wrapping / padding, each with a matching "
        "deobfuscator snippet and stats. Local, educational."
    ),
    category="redteam",
    mode="read",
    privileges="none",
    destructive=False,
    fields=[
        FieldSpec(name="marker", label="Marker text to obfuscate", type="textarea",
                  default="enter-your-marker-here"),
        FieldSpec(name="method", label="Obfuscation method", type="combo",
                  options=["xor", "base64", "xor-base64", "http-wrap"],
                  default="xor-base64"),
        FieldSpec(name="key", label="XOR key (bytes)", type="text",
                  default="securekey"),
        FieldSpec(name="output_dir", label="Output directory", type="dir",
                  default=None),
    ],
)


def _xor_encode(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _http_wrap(payload: bytes) -> bytes:
    rand = "".join(random.choice(string.ascii_letters) for _ in range(8))
    head = (f"GET /{rand.title()}/ HTTP/1.1\r\n"
            "Host: example.net\r\n"
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n"
            "Cookie: session=abc123\r\n\r\n").encode()
    tail = b"\r\n\r\n<!-- padding -->" + b"." * 24
    return head + payload + tail


def _obfuscate(data: bytes, method: str, key: bytes) -> Dict[str, object]:
    if method == "xor":
        body = _xor_encode(data, key)
        note = f"single-byte-key XOR with key {key!r}"
    elif method == "base64":
        body = base64.b64encode(data)
        note = "base64 encoding"
    elif method == "xor-base64":
        body = base64.b64encode(_xor_encode(data, key))
        note = f"XOR({key!r}) -> base64"
    else:
        inner = _xor_encode(base64.b64decode(
            base64.b64encode(data)), key)
        body = _http_wrap(inner)
        note = "HTTP-like framing wrapping XOR'd body with padding"
    import math
    counts = [0] * 256
    for b in body:
        counts[b] += 1
    entropy = -sum((c / len(body)) * math.log2(c / len(body))
                   for c in counts if c) if body else 0.0
    return {"body": body, "note": note, "entropy": round(entropy, 3),
            "size_delta": len(body) - len(data)}


def _deobfuscator(method: str, key: bytes) -> str:
    if method == "xor":
        op = "bytes(b ^ key[i % len(key)] for i, b in enumerate(blob))"
    elif method == "base64":
        op = "base64.b64decode(blob)"
    else:
        op = ("base64.b64decode(blob)  # -> xor:\n"
              "payload = bytes(b ^ key[i % len(key)] for i, b in "
              "enumerate(xored))")
    return f"""# deobfuscator snippet (lab)
import base64
key = {key!r}
blob = <obfuscated bytes>  # copy from payload.bin
{op}
print(payload)
"""


def run(params: dict, ctx: ToolContext) -> dict:
    marker = str(params.get("marker") or "").strip()
    if not marker or marker == "enter-your-marker-here":
        raise ValueError("marker text is required")
    method = str(params.get("method") or "xor-base64")
    if method not in ("xor", "base64", "xor-base64", "http-wrap"):
        raise ValueError("unknown obfuscation method")
    key = str(params.get("key") or "securekey").encode()

    data = marker.encode("utf-8")
    result = _obfuscate(data, method, key)

    written = ""
    out_dir = params.get("output_dir")
    if out_dir:
        out = Path(str(out_dir))
        out.mkdir(parents=True, exist_ok=True)
        (out / "payload.bin").write_bytes(result["body"])
        (out / "deobfuscator.py").write_text(_deobfuscator(method, key),
                                             encoding="utf-8")
        written = str(out)

    return {
        "method": method,
        "marker_characters": len(marker),
        "obfuscated_bytes": len(result["body"]),
        "size_delta": result["size_delta"],
        "entropy": result["entropy"],
        "note": result["note"],
        "obfuscated_preview": result["body"][:120],
        "deobfuscator_snippet": _deobfuscator(method, key),
        "output_dir": written,
        "finished_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }


def render(result: dict) -> str:
    lines = [
        f"C2 obfuscation demo ({result['method']}): "
        f"{result['marker_characters']} chars -> {result['obfuscated_bytes']} "
        f"bytes ({result['size_delta']:+d}, entropy {result['entropy']})",
        f"  {result['note']}",
        f"  preview: {result['obfuscated_preview']!r}",
    ]
    if result.get("output_dir"):
        lines.append(f"  files written to {result['output_dir']}")
    else:
        # still show deobfuscator for transparency
        lines.append("  (set output-dir to save payload.bin + "
                     "deobfuscator.py)")
    return "\n".join(lines)