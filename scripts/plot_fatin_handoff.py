"""Regenerate figures from supplied CSV paths; never run an experiment."""

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "shared")]

from evaluation.handoff_audit import aggregate_trials, compare_summary, read_csv
from evaluation.handoff_plots import caption, render_figures


def generate(trials_csv, summary_csv, output, split, toolpolicy, latency_csv=None, latency_meta=None):
    caption(split)
    if output.exists():
        raise FileExistsError("Use a NEW output directory; existing tuning/holdout outputs are preserved")
    rows = read_csv(trials_csv)
    if any(r.get("split", split) != split for r in rows):
        raise ValueError("CSV split disagrees with explicit split")
    cells = aggregate_trials(rows)
    if compare_summary(cells, read_csv(summary_csv)):
        raise ValueError("reported summary differs from raw records")
    latency = read_csv(latency_csv) if latency_csv else []
    metadata = json.loads(latency_meta.read_text()) if latency_meta else {}
    inputs = [p for p in (trials_csv, summary_csv, latency_csv, latency_meta) if p]
    hashes = {str(p.resolve()): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    send = [r for r in rows if r["condition"] in {"B", "C"} and r["trial_type"] == "benign_send"]
    patterns = Counter((r["condition"], r["threshold"], r["decision"], r["tool_executed"], r["output_allowed"], r["block_stage"]) for r in send)
    sources = sorted({r["source"] for r in rows if r["trial_type"] in {"direct", "indirect"}})
    output.mkdir(parents=True, exist_ok=False)
    render_figures(output, cells, latency, metadata, split=split, sources=sources, toolpolicy=toolpolicy)
    report = {"split":split, "split_verification":"Explicit caller declaration; checked against row split when present. Legacy CSV has no split column.",
              "toolpolicy":toolpolicy, "input_sha256":hashes, "cells":cells,
              "benign_send_raw_patterns":[{"condition":k[0],"threshold":k[1],"decision":k[2],"tool_executed":k[3],
                                           "output_allowed":k[4],"block_stage":k[5],"count":n} for k,n in sorted(patterns.items())]}
    (output/"plot_audit.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    assert hashes == {str(p.resolve()):hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials-csv", type=Path, required=True)
    parser.add_argument("--summary-csv", type=Path, required=True)
    parser.add_argument("--latency-csv", type=Path)
    parser.add_argument("--latency-meta", type=Path)
    parser.add_argument("--split", choices=("tune", "holdout"), required=True)
    parser.add_argument("--toolpolicy", choices=("absent", "enabled"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generate(args.trials_csv,args.summary_csv,args.output,args.split,args.toolpolicy,args.latency_csv,args.latency_meta)
