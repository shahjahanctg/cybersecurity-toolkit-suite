# c2-obfuscation — C2 Traffic Obfuscation Demo (W7)

Demonstrates traffic-shaping methods C2 agents use: single-byte-key XOR,
base64, XOR→base64, and HTTP-like wrapper framing with random padding.
You supply the marker/config text; the tool prints the obfuscated form plus
stats and writes `payload.bin` + a matching `deobfuscator.py` when an output
dir is given.

## What it does NOT do
- No real C2 channel, no network traffic, no persistence or execution.
- Obfuscation ≠ encryption for actual security control.

## Authorized use
Educational study of detector-avoidance shapes for your own lab proof of
concepts. Creating real obfuscated C2 for use against others without written
authorization is illegal — do not.

## Prerequisites
None (stdlib).

## Usage
```bash
sec-toolkit c2-obfuscation --marker 'poll-pulse/config-1' \
    --method xor-base64 --key labkey --output-dir ./study
```

## Output
`{method, marker_characters, obfuscated_bytes, size_delta, entropy, note,
obfuscated_preview, deobfuscator_snippet, output_dir?}` and the written
`payload.bin` + `deobfuscator.py`.

## Safety notes
- Read/codegen only; nothing leaves the machine.
- `http-wrap` mimics innocuous GET framing — still only a local file.

## Limitations
- XOR keys are static demo keys; sizes are indicative not ARP/latency-real.
- The deobfuscator snippet is illustrative Python, not a hardened agent.

## Version
0.1.0