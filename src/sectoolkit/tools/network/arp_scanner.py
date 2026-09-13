"""ARP Scanner — W1 Network Recon.

Discovers live hosts + MAC addresses on a local subnet by sending ARP requests
(Ethernet broadcast). Requires CAP_NET_RAW / root on Linux, admin on Windows.

Authorized use only: scan subnets you own or are tasked to assess.
"""

from __future__ import annotations

import socket
import time
from typing import List, Optional

from ...core.netutil import cidr_to_network
from ...core.privileges import do_have_raw_sockets
from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="arp-scan",
    title="ARP Scanner",
    wave=1,
    description=(
        "Discover live hosts and their MAC addresses on a local Ethernet "
        "subnet using ARP requests. The scan never leaves the Layer-2 segment "
        "it runs on — it does not cross routers."
    ),
    category="network",
    mode="act",
    privileges="net_raw",
    fields=[
        FieldSpec(name="subnet", label="Subnet (CIDR)", type="text", required=True,
                  placeholder="192.168.1.0/24",
                  help="Local subnet to sweep, e.g. 192.168.1.0/24"),
        FieldSpec(name="timeout", label="Response timeout (s)", type="int", default=3,
                  help="Seconds to wait for ARP replies"),
        FieldSpec(name="iface", label="Interface (optional)", type="text", default="",
                  help="Network interface to use, e.g. eth0. Empty = auto"),
        FieldSpec(name="resolve_hosts", label="Resolve hostnames", type="bool", default=False,
                  help="Reverse-DNS each responder (adds latency)"),
        FieldSpec(name="save_csv", label="Save CSV", type="bool", default=False,
                  help="Write a CSV report into the output directory"),
    ],
)

def arp_scan(
    subnet: str,
    timeout: int = 3,
    iface: str = "",
    resolve_hosts: bool = False,
    should_stop=None,
) -> List[dict]:
    """Perform the ARP sweep and return a list of responder records."""
    from scapy.all import ARP, Ether, srp

    net = cidr_to_network(subnet)
    if net.num_addresses > 65536:
        raise ValueError(
            f"refusing to sweep {subnet}: {net.num_addresses} addresses exceeds "
            "the 65536-address safety limit")

    packet_timeout = max(1, int(timeout))
    answers, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
        timeout=packet_timeout,
        verbose=False,
        iface=iface or None,
        inter=0.01,
        stop_filter=lambda p: _stop_requested(should_stop),
    )

    hosts: List[dict] = []
    for sent, received in answers:
        ip = received.psrc
        mac = received.hwsrc
        name = ""
        if resolve_hosts and ip:
            try:
                name = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.gaierror, OSError):
                name = ""
        hosts.append({
            "ip": str(ip),
            "mac": str(mac),
            "hostname": name,
            "responder": _mac_is_broadcast(mac) is False,
        })
    return hosts


def _stop_requested(should_stop) -> bool:
    try:
        return bool(should_stop and should_stop.is_set())
    except AttributeError:
        return False


def _mac_is_broadcast(mac: str) -> bool:
    return mac.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")


def run(params: dict, ctx: ToolContext) -> dict:
    ok, detail = do_have_raw_sockets()
    if not ok:
        raise PermissionError(
            f"arp-scan needs raw socket capability to send ARP packets. "
            f"Detected: {detail}. On Linux run as root or grant CAP_NET_RAW; "
            "on Windows/macOS run as administrator.")

    subnet = str(params.get("subnet", "")).strip()
    timeout = int(params.get("timeout") or 3)
    iface = str(params.get("iface") or "")
    resolve = bool(params.get("resolve_hosts", False))
    should_stop = ctx.extra.get("stop_event")

    start = time.time()
    try:
        hosts = arp_scan(subnet, timeout=timeout, iface=iface,
                         resolve_hosts=resolve, should_stop=should_stop)
    except PermissionError:
        raise
    except OSError as exc:
        raise PermissionError(
            f"send/receive failed (missing packet capability or interface "
            f"problem): {exc}") from exc

    duration_ms = int((time.time() - start) * 1000)
    hosts.sort(key=lambda h: [int(p) for p in h["ip"].split(".")])

    out = {
        "subnet": subnet,
        "interface": iface or "auto",
        "scan_count": len(hosts),
        "duration_ms": duration_ms,
        "hosts": hosts,
    }

    if params.get("save_csv") and hosts:
        p = ctx.ensure_output_dir() / f"arp-scan-{int(time.time())}.csv"
        p.write_text(
            "ip,mac,hostname\n" +
            "\n".join(f"{h['ip']},{h['mac']},{h['hostname']}" for h in hosts),
            encoding="utf-8")
        out["csv_path"] = str(p)

    return out


def render(result: dict) -> str:
    lines = [
        f"ARP scan of {result['subnet']} (iface {result['interface']})",
        f"hosts found: {result['scan_count']}   duration: {result['duration_ms']} ms",
        "",
        f"{'IP':<18}{'MAC':<20}{'Hostname':<32}",
        "-" * 70,
    ]
    for h in result["hosts"]:
        lines.append(
            f"{h['ip']:<18}{h['mac']:<20}{h.get('hostname', ''):<32}")
    return "\n".join(lines)