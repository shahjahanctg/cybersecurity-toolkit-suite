# disk-image — Disk Image Acquirer (chain of custody) (W5)

Three modes for handling a raw disk/partition image:
- **hash** — SHA-256 + SHA-1 digests and size (read-only).
- **image** — byte-for-byte copy to `--output-dir/<src>.img` while hashing,
  plus a `.custody.json` record (investigator, case, both digests, timestamps).
- **verify** — recompute SHA-256 of a file and compare with `--expected-sha256`.

## What it does NOT do
- No wiping, partitioning, or writing to block devices (device output needs
  the OS copy tool of your choosing; this tool copies file-to-file).
- No compression or split spanning of the output image.

## Authorized use
Forensic acquisition and integrity checking of your own test images and lab
evidence files. Imaging a disk you do not own requires the owner's consent
and your org's evidence-handling policy.

## Prerequisites
None (pure standard library; 1 MiB read chunks).

## Usage
```bash
# just digest an image
sec-toolkit disk-image --input ./sd.img --mode hash \
    --investigator "Jane Doe" --case-id C-42

# create a hashed copy + custody record
sec-toolkit disk-image --input ./sd.img --mode image --output-dir ./case/

# verify a copy against a published digest
sec-toolkit disk-image --input ./case/sd.img.img --mode verify \
    --expected-sha256 <hex>
```

## Output
- hash/verify: `{sha256, sha1, size_bytes, verified_ok?}`.
- image: `{src_sha256, dst_sha256, copied_bytes, custody_json}` plus the
  written `.img` and `.custody.json`.

## Safety notes
- Declared read-only against the source; output goes only where you point it.
- Copy refuses to write onto the input itself.

## Limitations
- Block-device snapshots require external locking (LVM/LVM-vol snapshot,
  `dd`/`sfdisk`); this tool is file-oriented.
- Same host hashing/copy performance — no multi-threaded pipelining.

## Version
0.1.0