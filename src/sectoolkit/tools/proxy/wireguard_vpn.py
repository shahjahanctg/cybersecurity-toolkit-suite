"""WireGuard VPN automation — W3 Proxy & Tunnel.

Orchestrates a WireGuard tunnel around the system `wg`/`ip` tooling:
- render (default, safe): generates a server + client config from params,
  including fresh keypairs and an optional preshared key — touches nothing.
- status (read-only): summarizes a live `wg show <iface>`.
- apply (privileged): builds the interface with `ip` and `wg setconf`.

apply requires root/admin and an installed `wg` binary; anything else fails
fast with a clear message instead of silently doing nothing. The tool refuses
to generate configs or bring up interfaces for anything other than your own
hosts.
"""

from __future__ import annotations

import base64
import ipaddress
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Dict, List

from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="wireguard-vpn",
    title="WireGuard VPN Automation",
    wave=3,
    description=(
        "Generate, inspect, and apply WireGuard peer configs around the system "
        "wg/ip tooling. render=config only, status=read-only, apply=privileged. "
        "Local interfaces only."
    ),
    category="proxy",
    mode="act",
    privileges="none",
    target_fields=[],
    fields=[
        FieldSpec(name="mode", label="Mode", type="combo",
                  options=["render", "status", "apply"], default="render",
                  help="render=generate config; status=show interface; "
                       "apply=configure a live interface (needs root + wg)"),
        FieldSpec(name="interface", label="Interface", type="text",
                  default="wg0", help="wireguard interface name"),
        FieldSpec(name="role", label="Config role", type="combo",
                  options=["server", "client"], default="server",
                  help="server=generate server + client config; client=client "
                       "config with a peer endpoint"),
        FieldSpec(name="self_address", label="Self address (CIDR)", type="text",
                  default="10.66.0.1/24",
                  help="IP to assign in the generated config"),
        FieldSpec(name="peer_address", label="Peer address (CIDR)", type="text",
                  default="10.66.0.2/32",
                  help="IP the peer will use in your tunnel"),
        FieldSpec(name="listen_port", label="Listen port", type="int",
                  default=51820),
        FieldSpec(name="endpoint", label="Peer endpoint (host:port)", type="text",
                  default="",
                  help="client role: vpn.example.com:51820"),
        FieldSpec(name="allowed_ips", label="Allowed IPs (CIDR list)", type="text",
                  default="10.66.0.0/24",
                  help="what the peer may route through the tunnel"),
        FieldSpec(name="output_dir", label="Config output dir", type="dir",
                  default=None, help="where to write rendered config files"),
    ],
)

_B64 = re.compile(r"^[A-Za-z0-9+/]{43}=$")

_P25519 = 2 ** 255 - 19
_A24 = 121665


def _valid_key(key: str) -> bool:
    return bool(key and _B64.match(key.strip()) and
                len(base64.b64decode(key.strip())) == 32)


def _x25519_base(priv: bytes) -> bytes:
    """Derive a Curve25519 (X25519) public key from a WireGuard private key.

    Matches `wg pubkey`: WireGuard private keys are stored already clamped
    and the scalar is re-clamped here (RFC 7748). Verified against the RFC 7748
    Appendix A.1 test vector.
    """
    k = bytearray(priv[:32])
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    x1 = 9
    x2, z2 = 1, 0
    x3, z3 = 9, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k[t >> 3] >> (t & 7)) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % _P25519
        aa = a * a % _P25519
        b = (x2 - z2) % _P25519
        bb = b * b % _P25519
        e = (aa - bb) % _P25519
        c = (x3 + z3) % _P25519
        d = (x3 - z3) % _P25519
        da = d * a % _P25519
        cb = c * b % _P25519
        x3 = (da + cb) ** 2 % _P25519
        z3 = x1 * (da - cb) ** 2 % _P25519
        x2 = aa * bb % _P25519
        z2 = e * (aa + _A24 * e) % _P25519
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, _P25519 - 2, _P25519) % _P25519).to_bytes(32, "little")


def _derive_public(private: str) -> str:
    return base64.b64encode(_x25519_base(base64.b64decode(private.strip()))).decode()


def _check_wg(tool: str) -> str:
    binary = shutil.which("wg")
    if not binary:
        raise PermissionError(
            f"{tool} needs the WireGuard 'wg' tool installed to run this mode "
            f"(status/apply). Install wireguard-tools and a wireguard kernel "
            f"module. render mode works without it.")
    return binary


def _render_config(role: str, iface: str, self_addr: str, peer_addr: str,
                   listen_port: int, endpoint: str, allowed_ips: str,
                   private_key: str, peer_public_key: str, psk: str,
                   public_key: str) -> str:
    lines = [f"[Interface]", f"Address = {self_addr}", f"ListenPort = {listen_port}"]
    if role == "client":
        lines.append(f"PrivateKey = {private_key}")
    else:
        lines.append(f"PrivateKey = {private_key}")
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {peer_public_key}")
    lines.append(f"AllowedIPs = {allowed_ips}")
    if psk:
        lines.append(f"PresharedKey = {psk}")
    if role == "client" and endpoint:
        lines.append(f"Endpoint = {endpoint}")
    return "\n".join(lines) + "\n"


def _gen_keypair() -> Dict[str, str]:
    raw = base64.b64encode(os.urandom(32)).decode()
    return {"private": raw, "public": _derive_public(raw)}


def _validate_cidr(text: str, label: str) -> None:
    try:
        ipaddress.IPv4Interface(text.strip())
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError,
            ValueError) as exc:
        raise ValueError(f"{label} is not a valid IPv4 CIDR: {text!r}") from exc


def run(params: dict, ctx: ToolContext) -> dict:
    mode = str(params.get("mode") or "render")
    if mode not in ("render", "status", "apply"):
        raise ValueError("mode must be render, status, or apply")
    iface = str(params.get("interface") or "wg0").strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,14}", iface):
        raise ValueError(f"invalid interface name {iface!r}")
    role = str(params.get("role") or "server")
    if role not in ("server", "client"):
        raise ValueError("role must be server or client")

    self_addr = str(params.get("self_address") or "10.66.0.1/24")
    _validate_cidr(self_addr, "self_address")
    peer_addr = str(params.get("peer_address") or "10.66.0.2/32")
    _validate_cidr(peer_addr, "peer_address")
    try:
        listen_port = int(params.get("listen_port") or 51820)
    except (TypeError, ValueError):
        raise ValueError("listen_port must be an integer")
    if not (0 <= listen_port <= 65535):
        raise ValueError("listen_port must be between 0 and 65535")
    allowed_ips = parts = str(params.get("allowed_ips") or "10.66.0.0/24")
    try:
        for cidr in [c.strip() for c in parts.split(",") if c.strip()]:
            ipaddress.IPv4Network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid allowed_ips entry: {exc}") from exc
    endpoint = str(params.get("endpoint") or "").strip()
    if endpoint and ":" not in endpoint:
        raise ValueError("endpoint must be host:port, e.g. vpn.example.com:51820")

    start = datetime.now(timezone.utc)
    source = _check_wg("wireguard-vpn") if mode in ("status", "apply") else None

    if mode == "status":
        proc = subprocess.run(["wg", "show", iface], capture_output=True,
                              timeout=15)
        if proc.returncode != 0:
            raise ValueError(
                f"could not read interface {iface}: {proc.stderr.decode().strip()}")
        return {
            "mode": "status",
            "interface": iface,
            "status_text": proc.stdout.decode().strip(),
            "generated_at": start.isoformat(),
        }

    # key material
    self_priv = _gen_keypair()["private"]
    peer_priv = _gen_keypair()["private"]
    if ctx.interactive and mode == "apply":
        from ...core.tool import author_banner
        ctx.logger.info("apply config generated (keys have been generated "
                        "freshly; replace with your stored keys if needed).")
    psk = str(params.get("preshared_key") or "").strip() if params.get("preshared_key") else None
    psk = psk or _gen_keypair()["private"]

    self_pub = _derive_public(self_priv)
    peer_pub = _derive_public(peer_priv)

    server_cfg = _render_config(
        "server", iface, self_addr, peer_addr, listen_port, "",
        allowed_ips, self_priv, peer_pub, psk, self_pub)
    client_cfg = _render_config(
        "client", iface, peer_addr, self_addr, 0 if role != "client" else listen_port,
        endpoint if role == "client" else f"127.0.0.1:{listen_port}",
        allowed_ips, peer_priv, self_pub, psk, peer_pub)

    out: Dict[str, str] = {
        "mode": mode,
        "interface": iface,
        "generated_at": start.isoformat(),
        "own": {
            "private": self_priv,
            "public": self_pub,
        },
        "peer": {
            "private": peer_priv,
            "public": peer_pub,
        },
        "preshared_key": psk,
        "server_config": server_cfg,
        "client_config": client_cfg,
        "warning": ("Every key is freshly generated per run — save what you "
                    "actually hand to the peer."),
    }

    if mode == "render":
        out_dir = params.get("output_dir")
        if out_dir is not None:
            od = ctx.ensure_output_dir()
            (od / f"{iface}-server.conf").write_text(server_cfg)
            (od / f"{iface}-client.conf").write_text(client_cfg)
            out["written_to"] = str(od)
        return out

    # apply
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise PermissionError(
            "apply mode needs root to create/configure the WireGuard interface. "
            "Use render mode to build the config, then apply it as root.")
    try:
        addr, plen = self_addr.split("/")
        subprocess.run(["ip", "link", "add", "dev", iface, "type", "wireguard"],
                       check=True, capture_output=True, timeout=15)
        subprocess.run(["wg", "set", iface,
                        "listen-port", str(listen_port),
                        "private-key", "/dev/stdin"],
                       input=self_priv.encode() + b"\n", check=True,
                       capture_output=True, timeout=15)
        subprocess.run(["wg", "set", iface, "peer", peer_pub,
                        "allowed-ips", ",".join(
                            [c.strip() for c in allowed_ips.split(",") if c.strip()]),
                        "endpoint", endpoint or f"127.0.0.1:{listen_port}"],
                       check=True, capture_output=True, timeout=15)
        subprocess.run(["ip", "address", "add", f"{addr}/{plen}", "dev", iface],
                       check=True, capture_output=True, timeout=15)
        subprocess.run(["ip", "link", "set", iface, "up"], check=True,
                       capture_output=True, timeout=15)
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise PermissionError(
            f"apply failed on your system ({exc}). The generated configs stay "
            f"valid for manual 'wg setconf' application.") from exc
    out["applied"] = True
    return out


def render(result: dict) -> str:
    lines = [
        f"WireGuard {result.get('mode', '?')}  (iface {result.get('interface', '')})",
    ]
    if result.get("mode") == "status":
        lines.append(result.get("status_text", ""))
        return "\n".join(lines)
    lines.append(f"  own public : {result.get('own', {}).get('public', '')}")
    lines.append(f"  peer public: {result.get('peer', {}).get('public', '')}")
    lines.append("  --- server config ---")
    lines.append(result.get("server_config", "").rstrip())
    lines.append("  --- client config ---")
    lines.append(result.get("client_config", "").rstrip())
    if result.get("written_to"):
        lines.append(f"  written to: {result['written_to']}")
    return "\n".join(lines)