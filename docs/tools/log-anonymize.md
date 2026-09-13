# log-anonymize — Log Anonymizer (W2)

Produce an anonymized copy of a log file, replacing IPv4/IPv6 addresses, email
addresses, MAC addresses (and optional custom regexes) with stable placeholders
`[IP:1]`, `[EMAIL:2]` … or sha256-derived hash tokens.

## What it does NOT do
- Does not modify the original file.
- Does not redact everything: free-text secrets (API keys in prose) need your
  own `custom_patterns` regexes.
- Placeholders are not cryptographically safe against re-identification of
  low-entropy values (a common IP is guessable).

## Authorized use
Anonymizing logs you have rights to process (your apps, or data you hold under
a processing agreement) before sharing or publishing.

## Prerequisites
None — pure Python stdlib.

## Usage
```bash
# placeholder mode (recommended for review readability)
sec-toolkit log-anonymize --input access.log --output access-anon.log

# hash mode with a custom secret pattern
sec-toolkit log-anonymize --input auth.log --mode hash \
  --custom-patterns 'Bearer [A-Za-z0-9._-]+' --json
```

## Output
The anonymized file plus a report: input/output sizes, mode, per-category
redaction counts, `total_redactions`. Same input value → same replacement
within one run.

## Safety notes
- Refuses binary files (NUL bytes) and inputs over 200 MB.
- `errors="replace"` decode keeps streaming logs readable instead of failing.
- Clear results when done — anonymized material may still be sensitive.

## Limitations
- The IPv6 matcher is a practical subset, not a full RFC 4291 grammar.
- Hash mode tokens are stable per value, so repeated identical low-entropy
  values (e.g. the same emote) remain distinguishable.

## Version
0.1.0