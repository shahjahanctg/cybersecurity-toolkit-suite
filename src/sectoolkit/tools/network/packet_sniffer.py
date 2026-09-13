"""Packet Sniffer — W1 Network Recon.

Captures and summarizes packets on a network interface (needs raw sockets),
or reads a saved PCAP file offline (no privileges). Supports BPF-style
filters and saving captures for later review.

Capturing traffic you are not authorized to observe may be illegal. Only
sniff on networks you own or are explicitly permitted to monitor.
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional

from ...core.privileges import do_have_raw_sockets
from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="packet-sniff",
    title="Packet Sniffer",
    wave=1,
    description=(
        "Capture and summarize packets live on an interface (requires "
        "CAP_NET_RAW/root) or read a PCAP file offline. Supports BPF filters "
        "and saving captures for review."
    ),
    category="network",
    mode="read",
    privileges="net_raw",
    fields=[
        FieldSpec(name="mode", label="Mode", type="combo", default="live",
                  options=["live", "offline"],
                  help="live: capture from an interface; offline: analyze a PCAP file"),
        FieldSpec(name="interface", label="Interface", type="text", default="",
                  placeholder="eth0 (live mode)",
                  help="Interface to capture on; empty selects the default"),
        FieldSpec(name="filter", label="BPF filter", type="text", default="",
                  placeholder="tcp port 80  or  icmp",
                  help="Optional Berkeley Packet Filter expression"),
        FieldSpec(name="count", label="Packet count", type="int", default=0,
                  help="Max packets to capture (0 = until timeout)"),
        FieldSpec(name="timeout", label="Timeout (s)", type="int", default=10,
                  help="Stop capturing after this many seconds"),
        FieldSpec(name="save_pcap", label="Save PCAP", type="dir", default="",
                  help="Directory to save a capture; empty = do not save"),
        FieldSpec(name="pcap_file", label="PCAP file (offline)", type="file", default="",
                  help="PCAP file to analyze in offline mode"),
    ],
)


def _summarize(packet) -> Dict[str, Optional[str]]:
    """Extract a small, JSON-safe summary of one packet."""
    from scapy.packet import Raw
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether

    summary: Dict[str, Optional[str]] = {
        "time": str(getattr(packet, "time", "")),
        "length": int(getattr(packet, "len", 0) or 0),
        "src": None, "dst": None, "proto": None,
        "sport": None, "dport": None, "payload": None,
    }
    if packet.haslayer(Ether):
        eth = packet[Ether]
        summary["src"] = eth.src
        summary["dst"] = eth.dst
    if packet.haslayer(IP):
        ip = packet[IP]
        summary["src"] = summary["src"] or ip.src
        summary["dst"] = summary["dst"] or ip.dst
        try:
            summary["proto"] = ip.proto
        except Exception:
            pass
    if packet.haslayer(TCP):
        t = packet[TCP]
        summary["proto"] = "tcp"
        summary["sport"], summary["dport"] = t.sport, t.dport
    elif packet.haslayer(UDP):
        u = packet[UDP]
        summary["proto"] = "udp"
        summary["sport"], summary["dport"] = u.sport, u.dport
    elif packet.haslayer(ICMP):
        summary["proto"] = "icmp"
    if packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        try:
            summary["payload"] = payload.decode("utf-8", errors="replace")[:200]
        except Exception:
            summary["payload"] = payload[:60].hex()
    return summary


def analyze_pcap(path: str, filter_spec: str, max_count: int) -> tuple:
    """Offline analysis: load a PCAP and summarize matching packets."""
    from scapy.all import rdpcap
    from scapy.error import Scapy_Exception

    try:
        packets = rdpcap(path)
    except (OSError, Scapy_Exception) as exc:
        raise ValueError(f"cannot read pcap {path!r}: {exc}") from exc

    summaries: List[Dict[str, Optional[str]]] = []
    for pkt in packets:
        if filter_spec and not _matches(pkt, filter_spec):
            continue
        if max_count and len(summaries) >= max_count:
            break
        summaries.append(_summarize(pkt))
    return summaries, len(packets)


def _matches(packet, filter_spec: str) -> bool:
    from scapy.layers.inet import TCP, UDP, IP
    from scapy.layers.l2 import Ether
    f = filter_spec.strip().lower()
    if not f:
        return True
    tokens = sorted(t for t in f.replace("/", " ").split())
    for token in tokens:
        if token == "tcp" and not packet.haslayer(TCP):
            return False
        if token == "udp" and not packet.haslayer(UDP):
            return False
        if token == "icmp" and not packet.haslayer("ICMP"):
            return False
        if token == "ip" and not packet.haslayer(IP):
            return False
        if token.startswith("port"):
            continue
    # apply simple 'port N' filter
    if "port" in tokens:
        idx = tokens.index("port")
        if idx + 1 < len(tokens):
            try:
                port = int(tokens[idx + 1])
            except ValueError:
                return True
            tcp = packet.getlayer(TCP)
            udp = packet.getlayer(UDP)
            if tcp is None and udp is None:
                return False
            port_layer = tcp or udp
            if port_layer and port not in (port_layer.sport, port_layer.dport):
                return False
    return True


def run(params: dict, ctx: ToolContext) -> dict:
    mode = params.get("mode", "live")
    if mode == "offline":
        pcap = str(params.get("pcap_file") or "").strip()
        if not pcap:
            raise ValueError("offline mode requires a pcap_file")
        filter_spec = str(params.get("filter") or "")
        max_count = int(params.get("count") or 0)
        start = time.time()
        summaries, total = analyze_pcap(pcap, filter_spec, max_count)
        return {
            "mode": "offline",
            "pcap_file": pcap,
            "total_packets_in_file": total,
            "summarized": len(summaries),
            "duration_ms": int((time.time() - start) * 1000),
            "packets": summaries,
        }

    ok, detail = do_have_raw_sockets()
    if not ok:
        raise PermissionError(
            f"live packet capture needs raw socket capability. Detected: "
            f"{detail}. On Linux run as root or grant CAP_NET_RAW; on "
            "Windows/macOS run as administrator. Offline mode (pcap_file) "
            "needs no privileges.")

    from scapy.all import sniff, wrpcap

    iface = str(params.get("interface") or "").strip() or None
    filter_spec = str(params.get("filter") or "").strip() or None
    count = int(params.get("count") or 0) or None
    timeout = int(params.get("timeout") or 10)
    save_dir = str(params.get("save_pcap") or "").strip()
    should_stop = ctx.extra.get("stop_event")

    captured: List[Dict[str, Optional[str]]] = []

    def _collect(pkt, captured=captured):
        if len(captured) <= 5000:
            captured.append(_summarize(pkt))

    stop_filter = None
    if should_stop is not None:
        def stop_filter(pkt, should_stop=should_stop):
            return bool(should_stop.is_set())

    start = time.time()
    try:
        pkts = sniff(
            iface=iface,
            filter=filter_spec,
            count=count,
            timeout=timeout,
            prn=_collect,
            store=True,
            stop_filter=stop_filter,
        )
    except (PermissionError, OSError) as exc:
        raise PermissionError(
            f"capture failed (missing privileges or bad interface): {exc}") from exc

    duration_ms = int((time.time() - start) * 1000)

    out = {
        "mode": "live",
        "interface": iface or "default",
        "filter": filter_spec or "",
        "captured": len(captured),
        "duration_ms": duration_ms,
        "packets": captured,
    }

    if save_dir:
        from pathlib import Path
        d = Path(save_dir)
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"capture-{int(time.time())}.pcap"
        try:
            wrpcap(str(path), pkts)
            out["pcap_path"] = str(path)
        except Exception as exc:  # pragma: no cover
            out["pcap_error"] = str(exc)

    return out


def render(result: dict) -> str:
    lines = []
    if result["mode"] == "offline":
        lines.append(
            f"Offline analysis of {result['pcap_file']}: "
            f"{result['summarized']}/{result['total_packets_in_file']} packets summarized")
    else:
        lines.append(
            f"Captured {result['captured']} packets on {result['interface']} "
            f"({result['duration_ms']} ms)")
    lines.append("")
    lines.append(f"{'#':<5}{'TIME':<14}{'SRC':<18}{'DST':<18}{'PROTO':<6}{'SPORT':<7}{'DPORT':<7}LEN")
    lines.append("-" * 85)
    for i, p in enumerate(result["packets"], start=1):
        ts = ""
        try:
            ts = f"{float(p['time']):.2f}"
        except (TypeError, ValueError):
            ts = str(p["time"] or "")
        lines.append(
            f"{i:<5}{ts:<14}{str(p['src'] or ''):<18}{str(p['dst'] or ''):<18}"
            f"{str(p['proto'] or ''):<6}{str(p['sport'] or ''):<7}{str(p['dport'] or ''):<7}"
            f"{p['length']}")
    if "pcap_path" in result:
        lines.append("")
        lines.append(f"saved capture: {result['pcap_path']}")
    return "\n".join(lines)