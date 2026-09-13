# persistence-catalog — Persistence Cataloger (W6)

Walks a directory tree you point it at and flags persistence/IOC indicators:
autostart / startup entries, init scripts, systemd units, cron lines, and
Windows "Run" keys exported in `.reg` files. Produces a grouped finding
report.

## What it does NOT do
- No registry hive parsing (binary `SYSTEM`/`NTUSER.DAT`), no WMI/scheduled
  task XML interpretation beyond cron-style text, no kernel drivers scan.
- Scan depth is textual — binaries are not disassembled for self-persistence.

## Authorized use
Reviewing your own machines or a lab filesystem image for suspicious
persistence after an incident. Pointing it at systems you do not own requires
written authorization.

## Prerequisites
None. Point the scanner at a mounted lab FS, an extracted config dump, or
`.` for the current user's live environment (read-only).

## Usage
```bash
sec-toolkit persistence-catalog --root . --deep --max-entries 500
```

## Output
`{root, findings_count, by_kind{}, findings[]}` — each finding
`{path, kind (systemd-unit|init-script|cron|autostart|registry-run), detail}`.

## Safety notes
- Read-only: it only reads files under `--root`; nothing is written.
- Files are read with bounded heads (4 KB) except `.reg` deep scans and
  `--deep` cron files.

## Limitations
- "systemd-unit"/"init-script" matching relies on the directory path containing
  `systemd`/`init.d`/`rc.d`; other layouts are missed.
- Cron detection skips `@reboot` style macros by design (they can be noisy);
  enable `--deep` only when you accept fuller scanning.

## Version
0.1.0