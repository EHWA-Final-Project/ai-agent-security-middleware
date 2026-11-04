"""Local-only real-package Reader/AppTest QA; writes no received data to Git."""

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src"), str(ROOT / "shared")]

from demo.benchmark_reader import load_holdout, load_tuning
from demo.reviewed_package import validate_directory


def check(directory):
    from streamlit.testing.v1 import AppTest

    directory = Path(directory).resolve()
    proof = validate_directory(directory)
    holdout = load_holdout(directory / "holdout")
    if holdout["errors"]:
        raise ValueError(holdout["errors"])
    tuning = load_tuning(directory / "tuning")
    os.environ["GUARDON_EVALUATION_HANDOFF"] = str(directory)
    app = AppTest.from_file(str(ROOT / "demo/dashboard.py"), default_timeout=60).run()
    if app.exception:
        raise AssertionError([e.message for e in app.exception])
    tables = [frame.value for frame in app.dataframe]
    full = next(
        frame
        for frame in tables
        if len(frame) == len(holdout["rows"]) and "numerator" in frame.columns
    )
    for expected in holdout["rows"]:
        subset = full[
            (full["policy"] == expected["policy"])
            & (full["condition"] == expected["condition"])
            & (full["metric"] == expected["metric"])
        ]
        subset = (
            subset[subset["threshold"].isna()]
            if expected["threshold"] is None
            else subset[subset["threshold"] == expected["threshold"]]
        )
        if (
            len(subset) != 1
            or subset.iloc[0]["numerator"] != expected["numerator"]
            or subset.iloc[0]["denominator"] != expected["denominator"]
        ):
            raise AssertionError("Dashboard numerator/denominator differs from Reader")
    if len(app.get("image")) != 8:
        raise AssertionError("Expected four Holdout and four Tuning graph panels")
    app.run()
    if app.exception or len(app.get("image")) != 8:
        raise AssertionError("Dashboard rerender failed")
    return {
        "status": "reviewed_dashboard_checked",
        "files_checked": proof["file_count"],
        "holdout_status": holdout["status"],
        "holdout_cells_per_sweep": 17,
        "tuning_cells": len(tuning["cells"]),
        "graph_panels": 8,
        "dashboard_rows_checked": len(holdout["rows"]),
        "runtime_execution_verified": False,
        "raw_trial_recalculation_performed_here": False,
        "browser_visual_qa_performed": False,
        "headline": [
            r
            for r in holdout["rows"]
            if r["threshold"] == 0.8
            and r["metric"]
            in ("attack_tool_execution", "pre_tool_block", "completion_read")
        ],
        "core_only_latency_ms": tuning["latency"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = check(args.package)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(
        json.dumps(
            {
                k: v
                for k, v in result.items()
                if k not in ("headline", "core_only_latency_ms")
            },
            ensure_ascii=True,
        )
    )


if __name__ == "__main__":
    main()
