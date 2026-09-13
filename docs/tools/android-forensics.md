# android-forensics — Android Forensics (W5)

Parses an adb Android backup archive (`.ab`, unencrypted v1/v2): validates
`ANDROID BACKUP` magic, reads version/flags/compression/encryption header
lines, decompresses the deflate payload, then either lists the contained tar
entries or extracts them (basename-only, traversal-safe) to an output dir.

## What it does NOT do
- No encrypted backups (AES) are decrypted — the tool refuses them: app data
  belongs to its owner; re-create the backup without a password.
- No `dm-verity`/`fs-verity` image parsing or app-sandbox forensic extraction
  beyond the adb backup format.

## Authorized use
Inspecting backups of devices you own (or debug `adb` dumps in a lab).
Backups can contain app credentials — guard the output accordingly.

## Prerequisites
None (stdlib `zlib` + `tarfile`). Create a backup on device with
`adb backup [-f file.ab] -apk -shared` (no password).

## Usage
```bash
# list entries
sec-toolkit android-forensics --backup ./device.ab --mode list

# extract interesting entries
sec-toolkit android-forensics --backup ./device.ab --mode extract \
    --output-dir ./device-shared
```

## Output
`{version, compressed, entry_count, entries[]}` — each entry
`{path, type, size, mtime}`; extract mode adds `extracted_files[]`.

## Safety notes
- Read-only against the backup; extraction writes only under the output dir.
- Extraction keeps each file's basename and skips `.`/`..` to prevent
  path-traversal writes from malicious archives.

## Limitations
- Unencrypted backups only; v1 stores entries under `apps/<pkg>/...` (kept
  as-is, no re-mapping).
- No incremental-backup (`FLAG_INCREMENTAL`) special handling — those are
  binary blobs, not tar, and will fail the tar parse with a clear message.

## Version
0.1.0