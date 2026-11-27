"""Plot completed-run backend latency from sanitized external MCP observations.

No model calls or private Evidence access. P95 uses linear interpolation.
"""

import argparse
import csv
import hashlib
import json
import math
import statistics
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def summarize(rows):
    if not isinstance(rows, list) or len(rows) != 48:
        raise ValueError("Expected the final 48-attempt trial export")
    keys = {(r["sample_id"], r["condition"]) for r in rows}
    samples = {r["sample_id"] for r in rows}
    if len(samples) != 12 or keys != {(s, c) for s in samples for c in "ABCD"}:
        raise ValueError("Incomplete or duplicate sample-condition coverage")
    if len({r["run_id"] for r in rows}) != 48:
        raise ValueError("Duplicate run identity")
    if any(r["status"] not in {"completed", "timeout", "error"} for r in rows):
        raise ValueError("Unexpected trial status")
    output = []
    for c in "ABCD":
        cohort = [r for r in rows if r["condition"] == c]
        values = []
        for r in cohort:
            if r["status"] != "completed":
                continue
            x = r["backend_latency_ms"]
            if r["evidence_validated"] is not True or isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x) or x < 0:
                raise ValueError("Invalid completed-run Evidence or latency")
            values.append(x / 1000)
        values.sort()
        if not values:
            raise ValueError(f"No eligible completed trials in {c}")
        k = .95 * (len(values) - 1)
        i = int(k)
        p95 = values[i] + (values[min(i + 1, len(values) - 1)] - values[i]) * (k - i)
        output.append({"condition": c, "completed": len(values), "attempted": len(cohort),
                           "excluded": len(cohort) - len(values), "mean_s": statistics.mean(values),
                           "p50_s": statistics.median(values), "p95_s": p95})
    if [r["completed"] for r in output] != [10, 10, 10, 11]:
        raise ValueError("Unexpected completion counts for the final experiment")
    return output


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    args = p.parse_args()
    data = args.input.read_bytes()
    rows = summarize(json.loads(data))
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    names = ["backend_latency.png", "backend_latency.svg", "backend_latency_summary.csv", "backend_latency_provenance.json"]
    if any((out / name).exists() for name in names):
        raise FileExistsError("Latency artifacts already exist; choose a fresh output directory")
    fig, ax = plt.subplots(figsize=(10, 5.3))
    width = .24
    for offset, key, label, color in [(-width, "mean_s", "Mean", "#4C78A8"),
                                     (0, "p50_s", "P50 (median)", "#72B7B2"),
                                     (width, "p95_s", "P95", "#F2A65A")]:
        bars = ax.bar([i + offset for i in range(4)], [r[key] for r in rows], width,
                      label=label, color=color)
        ax.bar_label(bars, fmt="%.1f", padding=3, fontsize=9)
    ax.set_xticks(range(4), [f"{r['condition']}\n(n={r['completed']}/12)" for r in rows])
    ax.set_ylabel("Backend execution latency (s)")
    ax.set_title("Completed-run backend latency by condition", loc="left", fontweight="bold", pad=16)
    ax.legend(ncol=3, loc="upper left", frameon=False)
    ax.set_ylim(0, max(r["p95_s"] for r in rows) * 1.24)
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(axis="y", alpha=.2)
    ax.set_axisbelow(True)
    fig.text(.10, .035, "41 completed trials; 5 timeouts and 2 errors excluded. Includes LLM inference; not isolated Guard overhead.\nDifferent completed sample sets; descriptive comparison only. P95: linear interpolation.", fontsize=9, color="#444444")
    fig.subplots_adjust(left=.10, right=.98, top=.88, bottom=.23)
    fig.savefig(out / names[0], dpi=180)
    fig.savefig(out / names[1])
    plt.close(fig)
    with (out / names[2]).open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    provenance = {"source_file": args.input.name, "source_sha256": hashlib.sha256(data).hexdigest(),
                  "unit": "seconds", "scope": "completed evidence-validated backend runs",
                  "p95_method": "linear interpolation", "completed": 41, "excluded": 7,
                  "inference_launched": False, "summary": rows}
    (out / names[3]).write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    for r in rows:
        print(f"{r['condition']}: n={r['completed']}/12, mean={r['mean_s']:.2f}, p50={r['p50_s']:.2f}, p95={r['p95_s']:.2f} s")
    print(f"Saved 4 latency artifacts to {out}")


if __name__ == "__main__":
    main()
