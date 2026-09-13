# wireless-wpa-audit — Wireless Auditor (WPA2 Handshake / PMKID) (W8)

Analyzes Wi-Fi captures **you already own** (offline pcap) for a WPA2
4-way handshake: EAPOL-Key frame count and message numbers (via the 802.1X
key-info bits), AP MAC, SSID, nonce/MIC presence, and any PMKID (or an
AP-supplied PMKID KDE) embedded in the key data. In `pmkid-check` mode it
runs your supplied passphrase through the real PSK derivation
(`PBKDF2-HMAC-SHA1` 4096, SSID-salted) to produce a candidate PMKID and
compares it against the captured value.

## What it does NOT do
- **No capture, no deauth, no injection, no monitor mode** — it never
  touches a radio or the network.
- No GPU/wordlist cracking; it verifies one passphrase at a time, offline.
- No MIC validation (that needs the pairwise keys / AES-CMAC), so a
  matching PMKID is evidence of the passphrase, not proof of a full
  handshake key.

## Authorized use
Offline ethical validation: audit only captures from APs/networks you own or
are explicitly authorized to test. Capturing or testing networks you do not
own is illegal in most jurisdictions.

## Prerequisites
None beyond the offline pcap (radiotap-free 802.11 frames are fine; scapy
also reads pcapng). The `pmkid-check` mode needs the SSID readable from the
capture (a beacon in the same file) or a PMKID you captured elsewhere.

## Usage
```bash
# report the handshake shape from a capture
sec-toolkit wireless-wpa-audit --pcap lab.pcap --mode handshake

# verify a passphrase candidate against the PMKID from the capture
sec-toolkit wireless-wpa-audit --pcap lab.pcap --mode pmkid-check \
    --passphrase 'phras3-vault' --output-dir ./report
```

## Output
`{mode, pcap_file, eapol_frames, frames[], ap_mac, ssid, pmkid,
nonce_present, mic_present, complete_handshake, state, verdict?}`; in
`pmkid-check` mode additionally `{candidate_pmkid, captured_pmkid,
pmkid_match, verdict}`. Writes `wpa-analysis.json` when an output dir is
given.

## Safety notes
- Read-only; the only writes are the JSON report you ask for.
- Messages are classified from the key-info bits (ACK/MIC/Secure) plus
  scapy's `guess_key_number()` when a pairwise EAPOL-Key is seen.

## Limitations
- Handshake classification is heuristic (msg2 with PMF-rekey shapes may
  mislabel); a "complete" verdict requires msg1..msg4 or msg1+msg3 with
  >=4 frames.
- STA MAC is not always derivable from a unidirectional capture, so the
  PMKID check defaults the missing side to `00:00:00:00:00:00` — pass an
  explicit captured PMKID when you have the real one.

## Version
0.1.0