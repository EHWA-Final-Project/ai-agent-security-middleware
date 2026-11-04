"""Audit imported CSV/JSONL without running experiments or copying model replies."""

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "shared")]

from evaluation.handoff_audit import (
    aggregate_trials,
    compare_summary,
    latency_summary,
    read_csv,
    read_jsonl,
)


def write_csv(path, rows):
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def generate(source, output):
    inventory = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in sorted(source.rglob("*")) if p.is_file()}
    trials = read_csv(source / "results/sweep_bc_tune_trials.csv")
    cells = aggregate_trials(trials)
    differences = compare_summary(cells, read_csv(source / "results/sweep_bc_tune_summary.csv"))
    pilot = source / "pilot_outputs_FROM_FATIN_LAPTOP"
    latency = latency_summary(read_jsonl(pilot / "latency.jsonl"))
    guards = read_csv(source / "results/guard_scores_tune.csv")
    if len({r["sample_id"] for r in guards}) != len(guards) or any(r["split"] != "tune" for r in guards):
        raise ValueError("Guard sample identity/split mismatch")
    grouped = defaultdict(list)
    for row in guards:
        grouped[(row["dataset"], row["subset"], row["label"], row["guard"])].append(row)
    detection = [{"dataset": key[0], "subset": key[1], "label": key[2], "guard": key[3],
                  "n": len(rows), "flagged": sum(float(r["risk_score"]) >= .5 for r in rows),
                  "rate": sum(float(r["risk_score"]) >= .5 for r in rows) / len(rows)}
                 for key, rows in sorted(grouped.items())]
    manifest = json.loads((source / "results/manifest.json").read_text())
    for d in detection:
        count = next(c["n"] for c in manifest["counts"] if c["split"] == "tune" and all(
            c[k] == d[k] for k in ("dataset", "subset", "label", "guard")))
        if count != d["n"]:
            raise ValueError("manifest Guard count mismatch")
    labels = read_jsonl(pilot / "jailbreak_judged_labels_only.jsonl")
    answers = read_jsonl(pilot / "dataset_answer.jsonl")
    traces = read_jsonl(pilot / "traces.jsonl")
    trace_counts = []
    for scenario, condition in sorted({(r["scenario"], r["condition"]) for r in traces}):
        selected = [r for r in traces if (r["scenario"], r["condition"]) == (scenario, condition)]
        trace_counts.append({"scenario": scenario, "condition": condition, "rows": len(selected),
                             "decisions": dict(Counter(str(r["decision"]) for r in selected)),
                             "send_email_calls": sum(r["send_email_calls"] for r in selected)})
    report = {"schema_version": "imported-fatin-audit-v1", "status": "arithmetic_audited",
              "evidence_validated": False, "split": "tune", "input_sha256": inventory,
              "summary_mismatches": differences, "raw_trial_rows": len(trials), "cells": cells,
              "guard_detection": detection, "latency": latency, "dataset_manifest": manifest,
              "latency_metadata": json.loads((pilot / "latency.jsonl.meta.json").read_text()),
              "pilots": {"jailbreak_label_counts": dict(Counter(r["judgment"] for r in labels)),
                         "jailbreak_judges": dict(Counter(r["judge"] for r in labels)),
                         "bipia_counts": dict(Counter(r["label"] for r in answers)),
                         "bipia_missing_judgments": sum(not r["judgment"] for r in answers),
                         "trace_rows": len(traces), "trace_counts": trace_counts},
              "toolpolicy_summary_status": "Reported only; raw trials absent; no independent verification"}
    output.mkdir(parents=True, exist_ok=False)
    (output / "audit_summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_csv(output / "recomputed_sweep.csv", cells)
    write_csv(output / "guard_detection.csv", detection)
    write_csv(output / "core_latency.csv", latency)
    from evaluation.handoff_plots import render_figures

    render_figures(output, cells, latency, report["latency_metadata"], split="tune",
                   sources=sorted({r["source"] for r in trials if r["trial_type"] in {"direct", "indirect"}}),
                   toolpolicy="absent")
    assert inventory == {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in source.rglob("*") if p.is_file()}
    print(json.dumps({"summary_mismatches":differences,"latency":latency,"detection":detection},indent=2))


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    generate(args.source,args.output)
