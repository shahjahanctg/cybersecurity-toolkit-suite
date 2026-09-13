"""Password Auditor + Wordlist Cracker — W4 Vuln Scanning.

Two offline modes around a bundled starter wordlist:
- audit: assess one (or more) passwords for length, character variety,
  entropy, common-password hits, year/sequence patterns.
- crack: crack md5/sha1/sha256/sha512 (optionally salted) hashes from a
  wordlist with light mutations.

No network calls — entirely local; nothing is exfiltrated.
"""

from __future__ import annotations

import hashlib
import math
import re
import string
from datetime import datetime, timezone
from typing import Dict, List

from ...core.datadir import read_lines
from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="password-auditor",
    title="Password Auditor + Cracker",
    wave=4,
    description=(
        "Offline password policy audit and wordlist-based hash cracking "
        "(md5/sha1/sha256/sha512, optional salt). Fully local, no network or "
        "external services."
    ),
    category="vulnscan",
    mode="read",
    privileges="none",
    target_fields=[],
    fields=[
        FieldSpec(name="mode", label="Mode", type="combo",
                  options=["audit", "crack"], default="audit"),
        FieldSpec(name="password", label="Password to audit", type="secret",
                  default="", help="audit mode"),
        FieldSpec(name="hash_input", label="Hashes (hex[:format] per line)", type="textarea",
                  default="", help="crack mode: 5f4dcc3b5aa765d61d8327deb882cf99:md5"),
        FieldSpec(name="salt", label="Salt (hex)", type="secret", default=""),
        FieldSpec(name="wordlist", label="Wordlist file", type="file", default=None),
        FieldSpec(name="formats", label="Hash formats", type="text",
                  default="md5,sha1,sha256,sha512", help="comma-separated; used when a hash has no suffix"),
        FieldSpec(name="mutations", label="Apply word mutations", type="bool",
                  default=True),
    ],
)

_YEARS = re.compile(r"20\d\d|19\d\d")


def _char_classes(pw: str) -> Dict[str, int]:
    classes = {
        "lower": sum(1 for c in pw if c in string.ascii_lowercase),
        "upper": sum(1 for c in pw if c in string.ascii_uppercase),
        "digit": sum(1 for c in pw if c.isdigit()),
        "symbol": sum(1 for c in pw if c not in string.ascii_letters
                      and not c.isdigit() and not c.isspace()),
    }
    return classes


def _entropy_bits(pw: str) -> float:
    pool = 0
    if any(c in string.ascii_lowercase for c in pw):
        pool += 26
    if any(c in string.ascii_uppercase for c in pw):
        pool += 26
    if any(c.isdigit() for c in pw):
        pool += 10
    if any(c not in string.ascii_letters and not c.isdigit() for c in pw):
        pool += 33
    if pool == 0:
        return 0.0
    return len(pw) * math.log2(pool)


def audit_password(pw: str) -> Dict[str, object]:
    checks: List[dict] = []
    score = 0
    verdict = "weak"

    if len(pw) >= 14:
        score += 3
    elif len(pw) >= 10:
        score += 2
    elif len(pw) >= 8:
        score += 1
    checks.append({"check": "length",
                   "detail": f"{len(pw)} characters",
                   "ok": len(pw) >= 10, "weight": 3 if len(pw) >= 14 else 2})
    cls = _char_classes(pw)
    variety = sum(1 for v in cls.values() if v > 0)
    checks.append({"check": "variety",
                   "detail": f"{variety}/4 classes "
                             f"(upper={cls['upper']}, lower={cls['lower']}, "
                             f"digit={cls['digit']}, symbol={cls['symbol']})",
                   "ok": variety >= 3, "weight": 2})
    if variety >= 4:
        score += 3
    elif variety >= 3:
        score += 2

    entropy = _entropy_bits(pw)
    checks.append({"check": "entropy",
                   "detail": f"~{entropy:.0f} bits",
                   "ok": entropy >= 60, "weight": 2})
    if entropy >= 80:
        score += 3
    elif entropy >= 60:
        score += 2

    common = pw.lower() in _COMMON
    checks.append({"check": "well-known",
                   "detail": "found in common-password list" if common else "not in common list",
                   "ok": not common, "weight": 3})
    if common:
        score -= 4

    if _YEARS.search(pw):
        checks.append({"check": "year-pattern", "detail": "contains a year",
                       "ok": False, "weight": 1})
    if re.search(r"(.)\1{2,}", pw):
        checks.append({"check": "repeat", "detail": "has repeated characters",
                       "ok": False, "weight": 1})
    if re.search(r"123|abc|qwerty|asdf|zxcv", pw.lower(),
                 re.IGNORECASE):
        checks.append({"check": "sequence", "detail": "contains a common sequence",
                       "ok": False, "weight": 1})
    if pw.strip() != pw:
        checks.append({"check": "whitespace", "detail": "leading/trailing whitespace",
                       "ok": False, "weight": 1})

    score = max(0, min(10, score))
    if score >= 8:
        verdict = "strong"
    elif score >= 5:
        verdict = "ok"
    return {"password_length": len(pw), "score": score, "verdict": verdict,
            "entropy_bits": round(entropy, 1), "checks": checks}


def read_lines_top() -> List[str]:
    from ...core.datadir import data_file
    return [l.strip() for l in
            data_file("top-passwords.txt").read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.startswith("#")]


_COMMON = {p.strip().lower() for p in read_lines_top()}


def _wordlist() -> List[str]:
    return read_lines("wordlist.txt")


def _mutations(word: str) -> List[str]:
    out = {word}
    out.add(word.capitalize())
    out.add(word.upper())
    for suffix in ("1", "123", "!", "@1", "2021", "2022", "2023", "2024", "0"):
        out.add(word + suffix)
        out.add(word.capitalize() + suffix)
    if re.match(r"^[a-z]+$", word) and len(word) >= 5:
        out.add(word[::-1])
    return [w for w in out if w]


HASHERS = {"md5": hashlib.md5, "sha1": hashlib.sha1,
           "sha256": hashlib.sha256, "sha512": hashlib.sha512}


def _digest(word: str, fmt: str, salt: bytes) -> str:
    hasher = HASHERS[fmt]
    if salt:
        return hasher(salt + word.encode("utf-8")).hexdigest()
    return hasher(word.encode("utf-8")).hexdigest()


def _parse_hashes(text: str, default_formats: List[str]) -> List[dict]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            h, _, fmt = line.partition(":")
        else:
            h, fmt = line, None
        h = h.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{32,128}", h):
            raise ValueError(f"not a valid hex hash: {line!r}")
        if fmt:
            if fmt not in HASHERS:
                raise ValueError(f"unknown format {fmt!r}")
            out.append({"hash": h, "format": fmt})
        else:
            fmt = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}.get(len(h))
            if fmt is None:
                raise ValueError(f"cannot infer format for {h[:16]}… "
                                 f"(use hash:format syntax)")
            out.append({"hash": h, "format": fmt})
    return out


def run(params: dict, ctx: ToolContext) -> dict:
    mode = str(params.get("mode") or "audit")
    if mode not in ("audit", "crack"):
        raise ValueError("mode must be audit or crack")
    start = datetime.now(timezone.utc)

    if mode == "audit":
        pw = str(params.get("password") or "")
        if not pw:
            raise ValueError("password is required for audit mode")
        return {
            "mode": "audit",
            "audit": audit_password(pw),
            "finished_at": start.isoformat(),
        }

    text = str(params.get("hash_input") or "").strip()
    if not text:
        raise ValueError("hash_input is required for crack mode")
    salt = bytes.fromhex(str(params.get("salt") or "").strip()) if params.get("salt") else b""
    default_formats = [f.strip() for f in
                       str(params.get("formats") or "md5,sha1,sha256,sha512").split(",")
                       if f.strip() in HASHERS]
    if not default_formats:
        default_formats = ["md5"]
    targets = _parse_hashes(text, default_formats)
    words = _wordlist()
    if params.get("wordlist"):
        words = _load_file_words(str(params["wordlist"]))
    mutate = bool(params.get("mutations", True))

    cracked: list = []
    attempts = 0
    uncracked = set()
    index: Dict[str, set] = {}
    for t in targets:
        index.setdefault(t["hash"].lower(), set()).add(t["format"])
    seen = set()

    for word in words:
        candidates = _mutations(word) if mutate else [word]
        for cand in candidates:
            for fmt in default_formats:
                hexd = _digest(cand, fmt, salt)
                if hexd in index and fmt in index[hexd]:
                    key = (hexd, cand)
                    if key not in seen:
                        seen.add(key)
                        cracked.append({
                            "hash": hexd, "format": fmt, "plaintext": cand})
            attempts += 1

    for t in targets:
        if not any(c["hash"] == t["hash"] for c in cracked):
            uncracked.add(t["hash"])

    cracked.sort(key=lambda c: c["hash"])
    return {
        "mode": "crack",
        "targets": len(targets),
        "cracked_count": len(cracked),
        "uncracked_count": len(uncracked),
        "attempts": attempts,
        "salt_hex": params.get("salt") or "",
        "cracked": cracked,
        "uncracked": sorted(uncracked),
        "finished_at": start.isoformat(),
    }


def _load_file_words(path: str) -> List[str]:
    return [w for w in open(path, encoding="utf-8", errors="replace").read().split() if w]


def render(result: dict) -> str:
    if result["mode"] == "audit":
        a = result["audit"]
        lines = [f"Password audit: {a['verdict'].upper()} — score {a['score']}/10 "
                 f"(~{a['entropy_bits']} bits)"]
        for c in a["checks"]:
            mark = "[OK]  " if c["ok"] else "[WARN]"
            lines.append(f"  {mark} {c['check']:<10} {c['detail']}")
        return "\n".join(lines)
    lines = [
        f"Cracker: {result['targets']} hashes, {result['cracked_count']} cracked "
        f"({result['attempts']} attempts)",
    ]
    for c in result.get("cracked", []):
        lines.append(f"  {c['format']:<8} {c['plaintext']!r}  <-  {c['hash'][:16]}…")
    for h in result.get("uncracked", []):
        lines.append(f"  (—)            {h[:16]}… NOT cracked")
    return "\n".join(lines)