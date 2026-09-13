# memory-forensics — Memory Forensics (W5)

Analyze a RAM dump two ways:
- **strings** — pure-Python extraction of printable strings for quick triage
  (process names, paths, URLs); writes `strings.txt` if an output dir is given.
- **vol** — run a Volatility 3 plugin (e.g. `windows.pslist.PsList`) against
  the dump and parse its JSON/CSV output; requires the `vol` binary.

## What it does NOT do
- No raw-structure parsing itself — Volatility mode shells out to `vol`.
- No carving of network artifacts/registry hives beyond what the chosen
  plugin produces.
- No kernel-mode analysis of live systems.

## Authorized use
Analyzing memory dumps from machines you own (or have authorization to
analyze). Dumps commonly contain sensitive material — treat them as evidence.

## Prerequisites
- strings mode: none.
- vol mode: a Volatility 3 install (`pip install volatility3`), binary passed
  with `--vol-binary` (default `vol` on PATH).

## Usage
```bash
# quick string triage
sec-toolkit memory-forensics --image ./ram.bin --mode strings \
    --output-dir ./triaged

# list running processes via Volatility
sec-toolkit memory-forensics --image ./ram.bin --mode vol \
    --plugin windows.pslist.PsList --vol-binary vol --output-dir ./reports
```

## Output
- strings: `{extracted, strings[], output_file?}` (up to `--top-strings`).
- vol: `{plugin, records, report[], output_file?}` (report capped at 100 KB
  in the result; full copy saved when an output dir is given).

## Safety notes
- Read-only on the dump; outputs go only to the chosen directory.
- `vol` runs with a 180 s timeout; a missing binary fails fast with install
  guidance rather than pretending to work.

## Limitations
- Plugin output is parsed as JSON only; non-JSON plugin output is returned
  as raw text with a `records` count of 1.
- String extraction is ASCII/UTF-8 printable only (no UTF-16).

## Version
0.1.0