# static-analysis — Static Analysis Pipeline (W6)

Parses PE / ELF containers and produces a triage dossier: machine type,
sections (with exec flags), bounded import listing (PE), ASCII/UTF-16
strings, MD5/SHA-1/SHA-256, whole-file Shannon entropy, and a packer
signature hint.

## What it does NOT do
- No dynamic analysis, disassembly, or opcode decoding.
- Imports are a bounded/best-effort parse; packed binaries often obscure them.
- Not a YARA engine — hand the dossier to `yara-rulegen`/`c2-extractor`.

## Authorized use
Triaging samples in a malware lab (samples you are authorized to possess and
analyze). Handle the sample per your org's isolation policy.

## Prerequisites
None (pure stdlib `struct`, `hashlib`, `re`).

## Usage
```bash
sec-toolkit static-analysis --sample ./sample.bin \
    --max-strings 200 --output-file ./report.json
```

## Output
`{format, container:{kind, machine, sections[], imports[], compiled_at}, 
sha256, sha1, md5, entropy, packed_hint, strings[], output_file?}` —
plus the JSON report when requested.

## Safety notes
- Read-only against the sample; nothing is executed.
- Report may echo binary strings — treat as untrusted data in your own tooling.

## Limitations
- ELF section-name extraction is best-effort; if the section header table is
  absent the sections list is empty.
- PE import walking stops after 64 DLLs / 96 thunks per DLL and requires a
  readable import directory.

## Version
0.1.0