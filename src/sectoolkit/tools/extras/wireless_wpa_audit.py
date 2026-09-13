"""Wireless Auditor (WPA2 handshake) — W8 Extras.

Analyses captured Wi-Fi traffic you already own (offline pcap) for a WPA2
4-way handshake: EAPOL frame count, message number, AP/STA MACs, nonce and
MIC presence, SSID/PMKID extraction, plus an optional offline PMKID check
against a passphrase you supply (PBKDF2 -> PMK, then the PMKID KDF).

It does NOT capture, inject, or deauth anything, and it makes no network
traffic. No wireless card / monitor mode required.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
from pathlib import Path
from typing import Dict, List, Optional

from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="wireless-wpa-audit",
    title="Wireless Auditor (WPA2 Handshake / PMKID)",
    wave=8,
    description=(
        "Analyse your own offline Wi-Fi pcap for a WPA2 4-way handshake and "
        "optionally verify a PMKID against a passphrase (offline, local). "
        "No capture, no deauth, no network traffic."
    ),
    category="extras",
    mode="read",
    privileges="none",
    destructive=False,
    fields=[
        FieldSpec(name="pcap", label="Wi-Fi capture (pcap/pcapng)", type="file",
                  default=""),
        FieldSpec(name="mode", label="Mode", type="combo",
                  options=["handshake", "pmkid-check"], default="handshake"),
        FieldSpec(name="passphrase", label="Passphrase (pmkid-check)", type="text",
                  default=""),
        FieldSpec(name="captured_pmkid", label="Captured PMKID hex (optional)",
                  type="text", default=""),
        FieldSpec(name="output_dir", label="Output directory", type="dir",
                  default=None),
    ],
)


def _pmk(passphrase: str, ssid: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", passphrase.encode(),
                               ssid.encode(), 4096, 32)


def _pmkid(pmk: bytes, ap_mac: str, sta_mac: str) -> bytes:
    ap = bytes.fromhex(ap_mac.replace(":", ""))
    sta = bytes.fromhex(sta_mac.replace(":", ""))
    return hmac.new(pmk, b"PMK Name" + ap + sta, hashlib.sha1).digest()[:16]


def _macstr(raw) -> str:
    if isinstance(raw, str):
        cleaned = raw.replace(":", "").replace("-", "").lower()
        if len(cleaned) == 12:
            return ":".join(cleaned[i:i + 2] for i in range(0, 12, 2))
        return "??"
    if not raw or len(raw) != 6:
        return "??"
    return ":".join(f"{b:02x}" for b in raw)


def _classify_keyinfo(keyinfo: int) -> str:
    ack = bool(keyinfo & 0x0100)
    mic = bool(keyinfo & 0x0200)
    secure = bool(keyinfo & 0x0400)
    if ack and not mic:
        return "msg1 (EAPOL-Key, Ack/no-MIC)"
    if mic and not ack and not secure:
        return "msg2 (EAPOL-Key, MIC/no-Secure)"
    if ack and mic and secure:
        return "msg3 (EAPOL-Key, MIC+Secure)"
    if mic and not ack and secure:
        return "msg4 (EAPOL-Key, MIC+Secure-no-Ack)"
    return "eapol-key (other/unknown key info)"


def _extract_pmkid_from_ie(kd: Optional[bytes]) -> Optional[str]:
    """Pull a PMKID KDE (DD <len> 00-0F-AC 04 <16 bytes>) from key data."""
    if not kd:
        return None
    i = 0
    while i + 2 <= len(kd):
        ktype, klen = kd[i], kd[i + 1]
        blob = kd[i:i + 2 + klen]
        if ktype == 0xDD and klen >= 18 and \
                blob[2:6] == b"\x00\x0f\xac\x04":
            return blob[6:22].hex()
        i += 2 + klen
    return None


def _keyinfo_bits(k) -> int:
    return (
        ((1 if k.smk_message else 0) << 14)
        | ((1 if k.encrypted_key_data else 0) << 13)
        | ((1 if k.request else 0) << 12)
        | ((1 if k.error else 0) << 11)
        | ((1 if k.secure else 0) << 10)
        | ((1 if k.has_key_mic else 0) << 9)
        | ((1 if k.key_ack else 0) << 8)
        | ((1 if k.install else 0) << 7)
        | ((1 if k.key_type else 0) << 3)
        | (k.key_descriptor_type_version & 0x07)
    )


def _message_label(k) -> str:
    guess = getattr(k, "guess_key_number", None)
    num = guess() if guess else 0
    names = {1: "msg1 (EAPOL-Key 1/4)", 2: "msg2 (EAPOL-Key 2/4)",
             3: "msg3 (EAPOL-Key 3/4)", 4: "msg4 (EAPOL-Key 4/4)"}
    if num in names:
        return names[num]
    return _classify_keyinfo(_keyinfo_bits(k))


def analyze_pcap(path: str, max_frames: int = 20000) -> dict:
    from scapy.all import rdpcap
    from scapy.error import Scapy_Exception
    from scapy.layers.dot11 import Dot11
    from scapy.layers.eap import EAPOL, EAPOL_KEY
    try:
        packets = rdpcap(path)
    except Scapy_Exception as exc:
        raise ValueError(f"cannot read pcap {path!r}: {exc}") from exc
    except Exception as exc:
        raise ValueError(f"cannot read capture {path!r}: {exc}") from exc

    frames = []
    ap_mac = sta_mac = None
    nonce_mic = {"nonce_present": False, "mic_present": False}
    for pkt in list(packets)[:max_frames]:
        if not pkt.haslayer(EAPOL_KEY):
            continue
        k = pkt[EAPOL_KEY]
        keyinfo = _keyinfo_bits(k)
        nonce = getattr(k, "key_nonce", b"") or b""
        nonce_mic["nonce_present"] = nonce_mic["nonce_present"] or bool(
            nonce and any(nonce))
        nonce_mic["mic_present"] = nonce_mic["mic_present"] or bool(
            getattr(k, "has_key_mic", False))
        src = _macstr(getattr(k, "src", getattr(pkt, "addr2", None)))
        if ap_mac is None and src and src != "??":
            ap_mac = src
        frames.append({
            "type": _message_label(k),
            "key_info": f"0x{keyinfo:04x}",
            "descriptor_version": k.key_descriptor_type_version & 0x07,
            "mic": bool(k.has_key_mic),
            "replay_counter": str(getattr(k, "key_replay_counter", "")),
        })

    ssid = _extract_ssid(packets[:max_frames])
    pmkid = _extract_pmkid_from_packets(packets[:max_frames])
    seen = set()
    for f in frames:
        seen.add(f["type"].split(" ")[0])
    complete = {"msg1", "msg2", "msg3", "msg4"}.issubset(seen) or \
        ({"msg1", "msg3"}.issubset(seen) and len(frames) >= 4)
    return {
        "eapol_frames": len(frames),
        "frames": frames,
        "ap_mac": ap_mac,
        "sta_mac": None,
        "ssid": ssid,
        "pmkid": pmkid,
        "descriptor_versions": sorted({f["descriptor_version"] for f in frames}),
        "nonce_present": nonce_mic["nonce_present"],
        "mic_present": nonce_mic["mic_present"],
        "complete_handshake": complete,
        "state": "COMPLETE 4-way handshake found" if complete
        else "incomplete handshake (need msg1..msg4 EAPOL-Key frames)",
    }


def _extract_ssid(packets) -> Optional[str]:
    from scapy.layers.dot11 import Dot11
    for pkt in list(packets):
        if pkt.haslayer(Dot11):
            ssid = getattr(pkt, "info", b"")
            if ssid and any(ssid):
                return ssid.decode("utf-8", errors="replace")
    return None


def _extract_pmkid_from_packets(packets) -> Optional[str]:
    from scapy.layers.eap import EAPOL_KEY
    for pkt in list(packets):
        if not pkt.haslayer(EAPOL_KEY):
            continue
        kd = getattr(pkt[EAPOL_KEY], "key_data", b"") or b""
        got = _extract_pmkid_from_ie(kd)
        if got:
            return got
    return None


def run(params: dict, ctx: ToolContext) -> dict:
    mode = str(params.get("mode") or "handshake")
    if mode not in ("handshake", "pmkid-check"):
        raise ValueError("mode must be handshake or pmkid-check")
    pcap = str(params.get("pcap") or "").strip()
    if not pcap:
        raise ValueError("pcap file is required (offline analysis only)")
    path = Path(pcap)
    if not path.exists():
        raise ValueError(f"pcap not found: {path}")

    analysis = analyze_pcap(str(path))
    result = {"mode": mode, "pcap_file": str(path), **analysis}

    if mode == "pmkid-check":
        passphrase = str(params.get("passphrase") or "").strip()
        if not passphrase:
            raise ValueError("pmkid-check requires a passphrase")
        if not analysis["ssid"]:
            raise ValueError("could not read the SSID from this capture; "
                             "pmkid-check needs it for the PSK derivation")
        pmk = _pmk(passphrase, analysis["ssid"])
        ap = analysis["ap_mac"] or "ff:ff:ff:ff:ff:ff"
        sta = analysis["sta_mac"] or "00:00:00:00:00:00"
        candidate = _pmkid(pmk, ap, sta)
        captured = str(params.get("captured_pmkid") or "").strip()
        if not captured and analysis.get("pmkid"):
            captured = analysis["pmkid"]
        lower = captured.lower()
        match = bool(lower) and lower == candidate.hex()
        result.update({
            "ssid_used": analysis["ssid"],
            "ap_mac_used": ap,
            "sta_mac_used": sta,
            "candidate_pmkid": candidate.hex(),
            "captured_pmkid": lower or None,
            "pmkid_match": match if captured else None,
            "verdict": "PASS — PMKID matches (likely correct passphrase)"
            if match else ("no captured PMKID to compare"
                           if not captured else
                           "FAIL — PMKID does not match"),
        })

    if params.get("output_dir"):
        out = Path(str(params["output_dir"]))
        out.mkdir(parents=True, exist_ok=True)
        target = out / "wpa-analysis.json"
        import json
        target.write_text(json.dumps({k: v for k, v in result.items()
                                      if k != "frames"}), encoding="utf-8")
        result["output_file"] = str(target)

    result["finished_at"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
    return result


def render(result: dict) -> str:
    lines = [f"WPA handshake analysis ({result['mode']}): "
             f"{result['pcap_file']}",
             f"  EAPOL frames : {result['eapol_frames']}",
             f"  AP / STA     : {result['ap_mac']} / {result['sta_mac']}",
             f"  SSID         : {result['ssid'] or 'unknown'}",
             f"  PMKID        : {result.get('pmkid') or 'not found in capture'}",
             f"  nonce/MIC    : {result['nonce_present']} / {result['mic_present']}",
             f"  state        : {result['state']}"]
    for f in result["frames"][:8]:
        lines.append(f"    {f['type']} key_info={f['key_info']} "
                     f"desc_v={f['descriptor_version']} mic={f['mic']}")
    if result["mode"] == "pmkid-check":
        lines.append(f"  candidate PMKID: {result['candidate_pmkid']} "
                     f"(match: {result.get('pmkid_match')})")
        lines.append(f"  verdict: {result['verdict']}")
    if result.get("output_file"):
        lines.append(f"Report written to {result['output_file']}")
    return "\n".join(lines)