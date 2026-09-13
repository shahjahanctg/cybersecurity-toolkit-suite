# unpack-tool — Unpacking / Deobfuscation Practice (W6)

Detects and decodes simple encoding/packing layers on a sample:
- **detect** — scans for base64 blobs, gzip/zlib streams, UPX/packer header
  markers, and high-entropy (possibly encrypted) blocks.
- **decode** — applies one chosen transform (`base64`, `gzip`, `zlib`,
  single-byte `xor`) and writes the prepared artifact to the output dir.

## What it does NOT do
- No real unpacking of compressed packers (UPX `-d` belongs to the lab
  toolchain, not this tool) and no multi-stage emulation.
- No shellcode deobfuscation or decryption-key recovery beyond single-byte XOR.

## Authorized use
Deobfuscation practice on lab samples you are authorized to handle. XOR keys
found are tool guesses — always verify against the sample's own loader.

## Prerequisites
None (stdlib `base64`, `zlib`, `gzip`).

## Usage
```bash
# see what layers are present
sec-toolkit unpack-tool --sample ./stage.bin --mode detect

# decode the base64 layer and save it
sec-toolkit unpack-tool --sample ./stage.bin --mode decode \
    --layer base64 --output-dir ./work

# brute single-byte XOR
sec-toolkit unpack-tool --sample ./xored.bin --mode decode \
    --layer xor --output-dir ./work
```

## Output
- detect: `{layers[], count, entropy_high}` — each layer `{name, detail, offset}`.
- decode: `{layer, decoded_bytes, detail, xor_key?, output_file?}` with a
  200-byte `decoded_preview`.

## Safety notes
- Read-only against the sample; outputs go only to the chosen directory.
- Decoded layers may be fresh malware payloads — keep them in the lab.

## Limitations
- XOR key guessing scores readability; short binary blobs can pick a wrong key.
- UPX "decode" is intentionally refused (header detection only) — use
  `upx -d` in a clean VM.

## Version
0.1.0