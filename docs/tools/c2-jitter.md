# c2-jitter — C2 Check-in Jitter / Sleep Study (W7)

Pure-math study of beacon check-in timing: given a base sleep and a jitter
percentage (0–100), it computes the actual delay window (sleep ± jitter%),
a deterministic sample schedule, mean, and total span, and writes
`beacon-timeline.csv` when an output dir is given. Designed as a
detector-engagement teaching aid for your own infrastructure.

## What it does NOT do
- No traffic generation, no agent code, no connections.

## Authorized use
Learning how timing-based network-visit detection sees beacons and why
jitter widens the detectable window. Use it to design *more detectable-by-
designator* lab beacons or understand blue-team thresholds.

## Prerequisites
None.

## Usage
```bash
sec-toolkit c2-jitter --sleep-base 60 --jitter-percent 20 \
    --iterations 24 --output-dir ./study
```

## Output
`{sleep_base, jitter_percent, delay_min_s, delay_max_s, mean_delay_s,
total_span_s, timeline[], analysis[], output_file?}` — timeline rows are
`{iter, delay_s, elapsed_s}`.

## Safety notes
- Math only; deterministic seed (42) for reproducibility.
- Delay samples obey `[sleep*(1-j), sleep*(1+j)]`; bounds are inclusive.

## Limitations
- Uniform sampling per interval (not Gaussian); real agents vary shape.

## Version
0.1.0