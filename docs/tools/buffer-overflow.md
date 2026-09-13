# buffer-overflow — Buffer Overflow Walkthrough (W7)

Educational walkthrough of classic stack-overflow exploitation shape:
- **cyclic** — generate a de Bruijn-style pattern to locate the EIP offset.
- **payload** — build the staging layout (junk + EIP overwrite + NOP sled +
  shellcode placeholder), filtering bad characters and respecting an
  endian-ordered return address.
- **walkthrough** — step-by-step guidance text.

Everything is computed locally; nothing is ever sent to a network target.

## What it does NOT do
- No exploit delivery, no debugger attachment, no real target interaction.
- The shellcode placeholder (`\xcc` x N) is hollow — you supply real
  shellcode in your own lab harness.

## Authorized use
Lab learning and development of exploits against **your own** crashable VM.
Exploiting any host you do not own is illegal without written authorization.
The built-in defaults (offset 146, JMP ESP `\x7d\x91\x08\x08`) are example
values, not target-derived.

## Prerequisites
None (pure stdlib; de Bruijn generation follows the standard mona-style
`Aa0Aa1...` scheme via 3-index cycling).

## Usage
```bash
# guidance
sec-toolkit buffer-overflow --mode walkthrough

# generate a cyclic pattern to send to your lab target
sec-toolkit buffer-overflow --mode cyclic --length 512

# build the payload file after you know the offset
sec-toolkit buffer-overflow --mode payload --offset 146 \
    --return-address '\x7d\x91\x08\x08' --bad-chars '\x00\x0a\x0d' \
    --shellcode-size 350 --output-dir ./exploit
```

## Output
- cyclic: `{length, pattern, hint}`.
- payload: `{offset, eip_raw, junk_bytes, bad_chars, payload_size,
  payload_hex, layout_summary, output_file?}`; writes `payload.bin` +
  `payload.txt` when an output dir is given.

## Safety notes
- The tool handles no network I/O — you must load the generated payload into
  your own authorized test harness (debugger/VM).
- A return address containing a bad character is rejected rather than
  silently mangled.

## Limitations
- Reflects the classic non-ASLR scenario only; modern mitigations (ASLR,
  CFG, stack cookies) are out of scope for the walkthrough.
- Bad-char handling is byte-list, not POS-edges etc.

## Version
0.1.0