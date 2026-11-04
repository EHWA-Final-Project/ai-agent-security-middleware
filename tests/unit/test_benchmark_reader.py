"""Synthetic reader fixtures are not experiment results."""

import hashlib
import json
import sys
from copy import deepcopy
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from demo.benchmark_reader import METRICS, THRESHOLDS, load_holdout


def payload():
    rows = []
    for mode, thresholds in (("A", [None]), ("B", THRESHOLDS), ("C", THRESHOLDS)):
        for threshold in thresholds:
            rows.append(
                {
                    "condition": mode,
                    "threshold": threshold,
                    "n_attack": 4,
                    "n_benign_read": 2,
                    "n_benign_send": 2,
                    **dict.fromkeys(METRICS, 0.5),
                }
            )
    return {
        "kind": "benchmark_evaluation",
        "split": "holdout",
        "run": {},
        "data": {},
        "headline_block_threshold": 0.8,
        "tool_policy": {},
        "notes": [],
        "sweep_default": rows,
        "sweep_with_tool_policy": deepcopy(rows),
        "c_block_cause": [],
    }


def write(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


def package(tmp_path):
    data = payload()
    write(tmp_path / "holdout_results.json", data)
    write(tmp_path / "run_record_holdout.json", {})
    sweeps = {}
    for name, field in (
        ("default", "sweep_default"),
        ("tool_policy", "sweep_with_tool_policy"),
    ):
        cells = []
        for row in data[field]:
            cell = {k: v for k, v in row.items() if k not in METRICS}
            cell["threshold"] = "" if row["condition"] == "A" else str(row["threshold"])
            for source, (metric, denominator) in METRICS.items():
                cell[metric + "_numerator"] = int(row[source] * row[denominator])
                cell[metric + "_denominator"] = row[denominator]
            cells.append(cell)
        sweeps[name] = {"cells": cells}
    raw = {
        "schema_version": "holdout-raw-verification-v1",
        "status": "raw_arithmetic_verified",
        "runtime_execution_verified": False,
        "mismatch_totals": {"summary_csv": 0},
        "input_sha256": {
            n: hashlib.sha256((tmp_path / n).read_bytes()).hexdigest()
            for n in ("holdout_results.json", "run_record_holdout.json")
        },
        "sweeps": sweeps,
    }
    write(tmp_path / "raw_verification.json", raw)
    return raw


def test_missing_directory(tmp_path):
    assert load_holdout(tmp_path / "absent")["status"] == "\uacb0\uacfc \uc5c6\uc74c"


def test_summary_without_schema_version_or_raw_is_insufficient(tmp_path):
    data = payload()
    write(tmp_path / "holdout_results.json", data)
    report = load_holdout(tmp_path)
    assert report["data"] == data
    assert report["raw"] is None
    assert all(row["numerator"] is None for row in report["rows"])
    assert report["runtime_execution_verified"] is False


@pytest.mark.parametrize(
    "change",
    [
        "split",
        "missing",
        "type",
        "nan",
        "zero",
        "duplicate",
        "coverage",
        "threshold",
        "bool",
        "fractional_count",
    ],
)
def test_invalid_summary_is_never_presented(tmp_path, change):
    data = payload()
    cell = data["sweep_default"][1]
    if change == "split":
        data["split"] = "tune"
    elif change == "missing":
        del cell["ASR"]
    elif change == "type":
        cell["ASR"] = "0.5"
    elif change == "nan":
        cell["ASR"] = float("nan")
    elif change == "zero":
        cell["n_attack"] = 0
    elif change == "duplicate":
        data["sweep_default"].append(deepcopy(cell))
    elif change == "coverage":
        data["sweep_default"].pop()
    elif change == "threshold":
        cell["threshold"] = "bad"
    elif change == "bool":
        cell["ASR"] = True
    elif change == "fractional_count":
        cell["n_attack"] = 2.5
    write(tmp_path / "holdout_results.json", data)
    report = load_holdout(tmp_path)
    assert report["errors"] and report["data"] is None and not report["rows"]


def test_string_thresholds_and_null_zero_population(tmp_path):
    data = payload()
    for row in data["sweep_default"]:
        row["threshold"] = "" if row["condition"] == "A" else str(row["threshold"])
        row["n_attack"] = 0
        row["ASR"] = row["pre_tool_block"] = None
    write(tmp_path / "holdout_results.json", data)
    assert load_holdout(tmp_path)["data"] is not None


def test_matching_raw_metadata_is_not_runtime_verification(tmp_path):
    package(tmp_path)
    report = load_holdout(tmp_path)
    assert not report["errors"]
    assert report["raw"] and report["rows"][0]["numerator"] == 2
    assert report["runtime_execution_verified"] is False


@pytest.mark.parametrize(
    "change", ["hash", "rate", "denominator", "mismatch", "runtime", "duplicate"]
)
def test_inconsistent_raw_rejected(tmp_path, change):
    raw = package(tmp_path)
    cell = raw["sweeps"]["default"]["cells"][0]
    if change == "hash":
        raw["input_sha256"]["holdout_results.json"] = "0" * 64
    elif change == "rate":
        cell["attack_tool_execution_numerator"] = 1
    elif change == "denominator":
        cell["attack_tool_execution_denominator"] = 5
    elif change == "mismatch":
        raw["mismatch_totals"]["summary_csv"] = 1
    elif change == "runtime":
        raw["runtime_execution_verified"] = True
    elif change == "duplicate":
        raw["sweeps"]["default"]["cells"].append(deepcopy(cell))
    write(tmp_path / "raw_verification.json", raw)
    assert load_holdout(tmp_path)["errors"]


def test_truncated_json(tmp_path):
    (tmp_path / "holdout_results.json").write_text("{", encoding="utf-8")
    assert load_holdout(tmp_path)["errors"]
