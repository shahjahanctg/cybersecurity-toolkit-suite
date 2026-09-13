# deleted-recovery — Deleted File Recovery (W5)

Signature-based carving of common file types (PNG, JPG, PDF, ZIP,
GIF, gzip, ELF) from a raw disk image. Files are deduplicated by content
hash and written to `--output-dir/recovered/` with an index, offset, and
hash baked into the name.

## What it does NOT do
- No full-filesystem parsing (FAT/NTFS/ext4 MFT indexing) — it does not know
  about the filesystem's deletion records, only byte signatures.
- No file reconstruction across fragmented extents (coalescing/hex-diff
  repair is out of scope for lab tooling).
- Carved slices may include slack garbage before the next signature.

## Authorized use
Recovering artifacts from your own test images and authorized evidence.
Operating on someone else's disk data requires their consent and applicable
evidence-handling policy.

## Prerequisites
None (pure stdin-read into memory; keep images small — see Limitations).

## Usage
```bash
sec-toolkit deleted-recovery --image ./sd.img --output-dir ./recovered \
    --min-size 512 --max-size 52428800
```

## Output
`{carved_count, recovered[]}` — per artifact `{kind, offset, size, sha256}`,
plus the physical `.bin` files under `recovered/`.

## Safety notes
- Read-only against the source image; writes only under the output dir.
- Recovery never writes to the source image itself.

## Limitations
- The whole image is read into memory (limit ~hundreds of MB in the GUI).
  For larger disks, pre-extract a partition or slack with `dd`.
- Carving stops at the *next* occurrence of the same signature, so a
  fragmented file may be truncated at `--max-size`.

## Version
0.1.0