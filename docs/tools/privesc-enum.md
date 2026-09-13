# privesc-enum — Privilege Escalation Enum (W7)

Read-only local scan for common Linux privilege-escalation candidates: SUID /
SGID binaries and world-writable executables in the standard binary dirs,
writable cron/systemd/autostart/init directories, world-writable PATH
components, uid-0 duplicate entries in `/etc/passwd`, and the running kernel
string for CVE comparison.

## What it does NOT do
- No exploit attempts, no kernel CVE auto-checking (you compare the kernel
  string yourself), no Windows deep scan (platform note only on non-Linux).

## Authorized use
Post-engagement hardening and lab recon on **your own** machines and lab VMs.
Running it on systems you do not own requires written authorization.

## Prerequisites
None. System binary dirs (SUID/writable) need read permissions; `--scan-bins`
can be disabled if directories are unreadable.

## Usage
```bash
sec-toolkit privesc-enum --scan-bins --max-bins 100 --output-dir ./report
```

## Output
`{os, platform_line, findings_count, findings[]}` — each finding
`{kind, path, detail}`. Saved as `privesc-report.json` when an output dir is
given.

## Safety notes
- Read-only: stat/read only, nothing written except the report you request.
- Scans are bounded and permission-failures degrade gracefully.

## Limitations
- Uses `/etc/passwd` for uid-0 duplicates (not NSS); cron checks cover
  `/etc/cron.d*` + parent-dir writability, not `at`/`anacron`.
- No command substitution via `sudo -l` and no `/proc` mount checks.

## Version
0.1.0