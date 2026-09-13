# persistence-rules — Persistence Catalog + Detection Rules (W7)

Turns a persistence catalog (JSON output of the W6 `persistence-catalog`
tool) — or a direct directory scan — into Sigma-style YAML detection rules
and a mechanism matrix. Each suspicious finding produces a rule file with a
stable `id`, `title`, `logsource`, `detection.selection`, and a bounded path/
detail matcher.

## What it does NOT do
- No execution of anything it scans; no live process-tree correlation.
- Rules are *experimental* Sigma skeletons — validate `endswith()`/field
  mapping against your SIEM's schema before use.

## Authorized use
Downgrading persistence candidates into analytics on environments you own.
Honest rule hygiene prevents alert fatigue on real defences.

## Prerequisites
None. Either a catalog JSON (preferred) or a `--root` directory to scan
internally via the W6 scanner.

## Usage
```bash
# derive rules from a catalog you produced earlier
sec-toolkit persistence-rules --catalog-json ./catalog.json \
    --output-dir ./rules

# or scan a tree and generate rules in one go
sec-toolkit persistence-rules --root ./lab-fs --output-dir ./rules
```

## Output
`{findings_count, by_kind{}, rules_count, rules[], written_rules[]}` — each
rule `{title, kind, path, detail, sigma}`; files are written under the output
dir when provided.

## Safety notes
- Read-only (catalog or file scan of the tree you pass).
- Rule file names derive from the finding title; no shell interpolation.

## Limitations
- Rule `selection` uses a single `Path`/`Details` matcher — multi-condition
  rules are out of scope; refine in your SIEM.
- id synthesized deterministically from the run (not a true UUID).

## Version
0.1.0