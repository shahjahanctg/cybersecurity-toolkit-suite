# yara-rulegen — YARA Rule Generator + Classifier (W6)

Two modes:
- **generate** — build a starter YARA rule from the sample's most signal-rich
  strings (mixed-case / digit-heavy, noise-filtered, length-thresholded).
- **classify** — heuristic tags (packers, API-abuseful patterns, anti-sandbox,
  mimikatz/keylogger/persistence hints) and, when a `.yar` file is supplied,
  report which rule strings are present in the target.

## What it does NOT do
- No full YARA engine — string-presence matching only (no hex patterns,
  wildcards, or condition DSL). Real detections should be validated against
  the official yara compiler.
- Generated rules are *starting points*, not production signatures.

## Authorized use
Creating detection rules for samples you are authorized to analyze in a lab.
Do not publish detection rules for samples you were given under NDA without
permission.

## Prerequisites
None.

## Usage
```bash
# generate a rule from a sample
sec-toolkit yara-rulegen --sample ./mal.exe --rule-name my_mal \
    --output-file ./my_mal.yar

# classify + match against an existing rule
sec-toolkit yara-rulegen --sample ./mal.exe --mode classify \
    --rule-file ./known.yar
```

## Output
- generate: `{rule_name, strings_used, strings[], rule_text, output_file?}`.
- classify: `{tags[], rule_strings_present[], rule_strings_total}`.

## Safety notes
- Read-only against the sample.
- Generated `.yar` is written only where you point it.

## Limitations
- Rule noise filtering is heuristic; short repetitive samples may produce a
  rule with few or zero strings (embeds a `false` placeholder in that case).
- Rule names are sanitized to `[A-Za-z0-9_]`.

## Version
0.1.0