"""Firewall Auditor — W2 Defense & Monitoring.

Read-only posture audit of the host firewall:

  * Linux: parses `iptables-save` or `nft list ruleset` (root usually needed
    to read) for chain policies, rule counts, and jump targets.
  * Linux listening ports: parsed from /proc/net/tcp{,6} + ss when available.
  * Windows: invokes `netsh advfirewall` (summarised, limited parsing).

The tool never modifies firewall state.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
import time
from typing import Dict, List

from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="firewall-audit",
    title="Firewall Auditor",
    wave=2,
    description=(
        "Read-only posture audit of the host firewall: chain policies, rule "
        "counts, jump targets, listening ports, and permissive-policy "
        "warnings. Supports Linux iptables/nftables and a basic Windows pass."
    ),
    category="defense",
    mode="read",
    privileges="none",
    fields=[
        FieldSpec(name="backend", label="Backend", type="combo",
                  default="auto", options=["auto", "iptables", "nftables", "windows"],
                  help="auto: detect; iptables/nftables: Linux; windows: netsh"),
        FieldSpec(name="check_listening", label="List listening ports",
                  type="bool", default=True,
                  help="Parse local listening TCP/UDP ports (no privileges)"),
        FieldSpec(name="timeout", label="Command timeout (s)", type="int", default=10,
                  help="Per external command timeout"),
    ],
)

_IPTABLES_CHAIN_RE = re.compile(r":(\S+)\s+(\S+)\s+\[(\d+):(\d+)\]")
_IPTABLES_RULE_RE = re.compile(r"-A\s+(\S+)\s+(.*)")
_IPTABLES_ARGS_RE = re.compile(r"(--?[a-z0-9-]+)(?:\s+(\S+))?")
_NFT_POLICY_RE = re.compile(r"policy\s+(accept|drop|reject)", re.IGNORECASE)
_NFT_DROP_RE = re.compile(r"\b(drop|reject)\b", re.IGNORECASE)


def parse_iptables_save(text: str) -> Dict[str, dict]:
    """Parse `iptables-save` output into per-table per-chain structure."""
    tables: Dict[str, Dict[str, dict]] = {}
    current_table = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("*"):
            current_table = line[1:]
            tables.setdefault(current_table, {})
        elif line.startswith(":") and current_table:
            m = _IPTABLES_CHAIN_RE.match(line)
            if m:
                name, policy = m.group(1), m.group(2)
                tables[current_table].setdefault(name, {
                    "policy": policy.lower() if policy != "-" else None,
                    "rules": [], "rule_count": 0})
        elif line.startswith("-A") and current_table:
            m = _IPTABLES_RULE_RE.match(line)
            if m:
                chain = m.group(1)
                spec = m.group(2)
                if chain in tables[current_table]:
                    tables[current_table][chain]["rules"].append(spec)
                    tables[current_table][chain]["rule_count"] += 1
    return tables


def summarize_iptables(tables: Dict[str, Dict[str, dict]]) -> List[dict]:
    """Flatten per-chain summary with policy and count of rule jump targets."""
    out = []
    for table, chains in tables.items():
        for chain, info in chains.items():
            jumps: Dict[str, int] = {}
            targets = []
            for rule in info["rules"]:
                t = _chain_target(rule)
                if t:
                    targets.append(t)
                    jumps[t] = jumps.get(t, 0) + 1
            out.append({
                "table": table,
                "chain": chain,
                "policy": info["policy"],
                "rule_count": info["rule_count"],
                "targets": dict(sorted(jumps.items(), key=lambda kv: -kv[1])),
            })
    return out


def _chain_target(spec: str) -> str:
    """Extract the jump target (-j X) from an iptables rule spec."""
    match = re.search(r"-j\s+(\S+)", spec)
    if not match:
        return ""
    target = match.group(1)
    return target if not target.startswith("!") else target[1:]


def parse_nft_ruleset(text: str) -> List[dict]:
    """Parse `nft list ruleset` into per-chain summaries + policies."""
    chains: List[dict] = []
    current = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("chain "):
            name = line.split()[1].rstrip(" {")
            current = {"chain": name, "policy": None, "rule_count": 0}
            chains.append(current)
        elif current is not None:
            if "policy " in line:
                m = _NFT_POLICY_RE.search(line)
                if m:
                    current["policy"] = m.group(1)
            if "drop" in line.lower() or "reject" in line.lower():
                if "policy" not in line and _NFT_DROP_RE.search(line):
                    current["rule_count"] += 1
    return chains


def _run_tool(cmd: List[str], timeout: int) -> str:
    if not shutil.which(cmd[0]):
        raise ValueError(f"required command not found: {cmd[0]} "
                         "(install it or choose another backend)")
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"command timed out: {' '.join(cmd)}") from exc
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()[:300]
        raise PermissionError(
            f"{cmd[0]} failed (exit {proc.returncode}); this usually means "
            f"insufficient privilege to read the firewall: {stderr}")
    return proc.stdout or ""


def parse_proc_net_tcp(text: str) -> List[dict]:
    """Parse /proc/net/tcp listen rows into {port, addr, hex_addr} facts."""
    ports = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[1]
        state = parts[3]
        if state != "0A":  # LISTEN
            continue
        addr, _, port_hex = local.partition(":")
        try:
            port = int(port_hex, 16)
        except ValueError:
            continue
        if not (0 < port < 65536):
            continue
        ip = ".".join(str(int(addr[i:i + 2], 16))
                      for i in (6, 4, 2, 0)) if addr and addr != "00000000" else "0.0.0.0"
        try:
            service = socket.getservbyport(port)
        except OSError:
            service = ""
        ports.append({"port": port, "addr": ip, "service": service,
                      "proto": "tcp"})
    return ports


def _listening_ports_linux() -> List[dict]:
    ports = []
    try:
        text = open("/proc/net/tcp", encoding="utf-8").read()
        ports.extend(parse_proc_net_tcp(text))
    except OSError:
        pass
    try:
        text6 = open("/proc/net/tcp6", encoding="utf-8").read()
        ports.extend(parse_proc_net_tcp(text6))
    except OSError:
        pass
    return sorted(ports, key=lambda p: (p["port"], p["proto"]))


def _listening_ports_windows() -> List[dict]:
    out = _run_tool(["netstat", "-ano"], 10)
    ports = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0] not in ("TCP", "UDP"):
            continue
        local = parts[1]
        if local.endswith(":LISTENING") or parts[0] == "UDP":
            local = parts[1].rsplit(":", 1)[0] if parts[0] == "TCP" else local
        if ":" not in local:
            continue
        _, port_s = local.rsplit(":", 1)
        try:
            port = int(port_s)
        except ValueError:
            continue
        try:
            service = socket.getservbyport(port)
        except OSError:
            service = ""
        ports.append({"port": port, "addr": local.rsplit(":", 1)[0],
                      "service": service, "proto": parts[0].lower()})
    return ports


def run(params: dict, ctx: ToolContext) -> dict:
    backend = params.get("backend", "auto")
    timeout = int(params.get("timeout") or 10)
    check_listening = bool(params.get("check_listening", True))
    start = time.time()

    import platform as _platform
    system = _platform.system()
    if backend == "auto":
        if system == "Windows":
            backend = "windows"
        else:
            backend = "nftables" if shutil.which("nft") else "iptables"

    warnings: List[str] = []
    out: Dict[str, dict] = {"backend": backend, "chains": [], "warnings": []}

    if backend in ("iptables", "nftables", "auto"):
        candidates = (["nftables", "iptables"] if backend == "auto" else [backend])
        ruleset_result = None
        last_error = "no backend available"
        for cand in candidates:
            cmd = (["nft", "list", "ruleset"] if cand == "nftables"
                   else ["iptables-save"])
            if not shutil.which(cmd[0]):
                last_error = f"required command not found: {cmd[0]}"
                continue
            try:
                raw = _run_tool(cmd, timeout)
            except (ValueError, PermissionError, TimeoutError) as exc:
                last_error = str(exc)
                continue
            ruleset_result = (cand, raw)
            break

        if ruleset_result:
            chosen, tables_raw = ruleset_result
            out["backend"] = chosen
            if chosen == "iptables":
                parsed = parse_iptables_save(tables_raw)
                out["chains"] = summarize_iptables(parsed)
                out["tables"] = {k: sorted(v) for k, v in parsed.items()}
            else:
                out["chains"] = parse_nft_ruleset(tables_raw)
            for chain in out["chains"]:
                policy = chain.get("policy")
                if chain["chain"] in ("input", "INPUT") and policy == "accept":
                    warnings.append(
                        f"INPUT chain default policy is ACCEPT "
                        f"({chain.get('table', 'filter')}) — permissive posture")
            out["warnings"] = warnings
        else:
            out["ruleset_error"] = last_error
            out["warnings"].append(
                "ruleset could not be read (likely privileges); "
                "listening-port report still available")

    elif backend == "windows":
        out["raw_available"] = shutil.which("netsh") is not None
        if out["raw_available"]:
            raw = _run_tool(
                ["netsh", "advfirewall", "firewall", "show", "rule",
                 "name=all", "verbose"], timeout)
            out["raw_lines"] = len(raw.splitlines())
            out["warnings"].append(
                "Windows ruleset parsed only in brief; summarised counts are "
                "not derived yet.")

    if check_listening:
        ports = (_listening_ports_windows() if backend == "windows"
                 else _listening_ports_linux())
        out["listening_ports"] = ports
        for p in ports:
            if p["port"] in (22, 23, 3389, 5900, 445, 139, 512, 513, 514, 2049):
                out["warnings"].append(
                    f"common attack surface listening: {p['proto']}/{p['port']} "
                    f"({p.get('service') or '?'}) on {p['addr']}")
        out["warning_count"] = len(out["warnings"])

    out["duration_ms"] = int((time.time() - start) * 1000)
    return out


def render(result: dict) -> str:
    lines = [f"Firewall audit (backend: {result['backend']})"]
    for chain in result.get("chains", []):
        policy = chain.get("policy") or "?"
        lines.append(
            f"  {chain.get('table', '') + '/' if chain.get('table') else ''}"
            f"{chain['chain']:<12} policy={policy:<8} rules={chain.get('rule_count', 0)}")
    ports = result.get("listening_ports", [])
    if ports:
        lines.append("")
        lines.append(f"Listening ({len(ports)}):")
        for p in ports[:50]:
            lines.append(
                f"  {p['proto']:<4} {p['port']:<6} {p.get('service') or '?':<14} {p['addr']}")
        if len(ports) > 50:
            lines.append(f"  … and {len(ports) - 50} more")
    if result.get("warnings"):
        lines.append("")
        lines.append("Warnings:")
        for w in result["warnings"]:
            lines.append(f"  ! {w}")
    return "\n".join(lines)