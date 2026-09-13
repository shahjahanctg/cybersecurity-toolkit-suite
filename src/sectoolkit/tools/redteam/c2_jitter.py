"""Agent Check-in Jitter / Sleep Study — W7 Red Team / C2.

A timing study behind C2 beacon jitter: given a base sleep interval and a
jitter percentage (0-100), compute the actual delay bounds
(base ± jitter%), expected mean, and a sample schedule timeline. Writes the
timeline as CSV when an output dir is given.

Pure math, no traffic.
"""

from __future__ import annotations

import datetime as _dt
import random
from pathlib import Path
from typing import List

from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="c2-jitter",
    title="C2 Check-in Jitter / Sleep Study",
    wave=7,
    description=(
        "Compute beacon check-in schedules: sleep base ± jitter%, mean delay, "
        "bounds, and a sample timeline (CSV on request). Educational study of "
        "timing-based detection vs. evasion. No traffic."
    ),
    category="redteam",
    mode="read",
    privileges="none",
    fields=[
        FieldSpec(name="sleep_base", label="Base sleep (seconds)", type="int",
                  default=60),
        FieldSpec(name="jitter_percent", label="Jitter (0-100%)", type="int",
                  default=20),
        FieldSpec(name="iterations", label="Timeline iterations", type="int",
                  default=15),
        FieldSpec(name="output_dir", label="Output directory (timeline.csv)",
                  type="dir", default=None),
    ],
)


def _schedule(base: float, jitter: float, n: int) -> List[float]:
    rng = random.Random(42)  # deterministic demo
    delays = []
    for _ in range(n):
        low = base * (1 - jitter)
        high = base * (1 + jitter)
        delays.append(rng.uniform(low, high) if jitter else float(base))
    return delays


def run(params: dict, ctx: ToolContext) -> dict:
    try:
        base = int(params.get("sleep_base") or 60)
        jitter = int(params.get("jitter_percent") or 20)
        n = int(params.get("iterations") or 15)
    except (TypeError, ValueError):
        raise ValueError("sleep_base/jitter_percent/iterations must be integers")
    if base < 0:
        raise ValueError("sleep_base must be >= 0")
    if not 0 <= jitter <= 100:
        raise ValueError("jitter_percent must be in 0-100")
    if n < 1:
        raise ValueError("iterations must be >= 1")

    delays = _schedule(base, jitter / 100.0, n)
    low = base * (1 - jitter / 100.0)
    high = base * (1 + jitter / 100.0)
    mean = sum(delays) / n
    total = sum(delays)
    timeline = []
    elapsed = 0.0
    for i, d in enumerate(delays, 1):
        elapsed += d
        timeline.append({"iter": i, "delay_s": round(d, 1),
                         "elapsed_s": round(elapsed, 1)})

    analysis = [
        f"base sleep    : {base}s",
        f"jitter applied: ±{jitter}% -> delays in "
        f"[{low:.1f}s, {high:.1f}s]",
        f"expected mean : ~{base}s (demo mean {mean:.1f}s)",
        f"total span    : {total:.1f}s across {n} check-ins",
        "detection note: fixed-period beacons are trivially clocked by "
        "network visits; jitter widens the window.",
    ]

    written = ""
    out_dir = params.get("output_dir")
    if out_dir:
        out = Path(str(out_dir))
        out.mkdir(parents=True, exist_ok=True)
        target = out / "beacon-timeline.csv"
        target.write_text("iter,delay_s,elapsed_s\n" + "\n".join(
            f"{t['iter']},{t['delay_s']},{t['elapsed_s']}" for t in timeline),
            encoding="utf-8")
        written = str(target)

    return {
        "sleep_base": base,
        "jitter_percent": jitter,
        "delay_min_s": round(low, 1),
        "delay_max_s": round(high, 1),
        "mean_delay_s": round(mean, 1),
        "total_span_s": round(total, 1),
        "timeline": timeline,
        "analysis": analysis,
        "output_file": written,
        "finished_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }


def render(result: dict) -> str:
    lines = [f"Check-in study: base {result['sleep_base']}s ±"
             f" {result['jitter_percent']}% -> "
             f"[{result['delay_min_s']}s, {result['delay_max_s']}s] "
             f"(mean {result['mean_delay_s']}s, total {result['total_span_s']}s)"]
    for t in result["timeline"][:8]:
        lines.append(f"  check-in {t['iter']:>2}: next in {t['delay_s']}s "
                     f"(elapsed {t['elapsed_s']}s)")
    lines.append("  ...")
    for a in result["analysis"]:
        lines.append(f"  # {a}")
    if result.get("output_file"):
        lines.append(f"Timeline saved to {result['output_file']}")
    return "\n".join(lines)