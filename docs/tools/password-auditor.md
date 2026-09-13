# password-auditor — Password Auditor & Cracker (W4)

Two modes:
- **audit** — scores a password 0–10 with granular checks (length, character
  variety, entropy, common-list membership, year/repeat/sequence patterns).
- **crack** — offline dictionary attack on unsalted MD5/SHA1/SHA256/SHA512
  hashes (optional hex salt), with a small mutation generator. Reads-only.

## What it does NOT do
- No brute-force GPU/rainbow cracking; dictionary + mutations only.
- No online/network guessing — hashes are local text.
- Bundle is tiny (curated wordlist) — hard passwords simply don't crack here.

## Authorized use
Self-audit: assess your own account policies and recover a password you forgot
from your own `passwd`-style dump in a lab. Do NOT run on passwords you do not
own.

## Prerequisites
None. Bundled `data/top-passwords.txt` and `data/wordlist.txt`. A custom
`--wordlist` file can be supplied for crack mode.

## Usage
```bash
# audit a password
sec-toolkit password-auditor --mode audit --password 'Tr0ub4dor&3-XyZ9!q7'

# crack a hash (format auto-inferred from 32/40/64/128 hex chars)
sec-toolkit password-auditor --mode crack --hash-input \
    '0192023a7bbd73250516f069df18b500'

# explicit format + salt + custom wordlist
sec-toolkit password-auditor --mode crack \
    --hash-input '5d41402abc4b2a76b9719d911017c592:md5' \
    --salt a1b2c3 --wordlist extra.txt --no-mutations
```

## Output
- audit: `{score, verdict, entropy_bits, checks[]}`.
- crack: `{targets, cracked_count, uncracked_count, attempts, cracked[],
  uncracked[]}` — per crack `{hash, format, plaintext}`.

## Safety notes
- Declared read-only; never touches the network.
- Password values are accepted via CLI args only; use the GUI's secret field
  for interactive sessions.

## Limitations
- Inferring a hash's format assumes the length implies MD5/SHA1/SHA256/SHA512;
  use `hash:format` syntax to pin it.
- Salt support is plain hex-prefix ("salted" like `md5(salt+pass)`), not
  PBKDF2/bcrypt — those formats are not supported.

## Version
0.1.0