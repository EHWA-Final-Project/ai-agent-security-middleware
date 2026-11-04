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


def test_owner_aggregate_and_raw_contract_integration(tmp_path):
    from scripts.verify_holdout_raw import verify_raw
    from tests.unit.test_verify_holdout_raw import fixture_files

    files = fixture_files()
    data = json.loads(files["holdout_results.json"])
    data.update(headline_block_threshold=0.8, tool_policy={}, notes=[])
    files["holdout_results.json"] = json.dumps(data).encode()
    record = json.loads(files["run_record_holdout.json"])
    record["policy"].update(headline_block_threshold=0.8, tool_policy_policy_run={})
    files["run_record_holdout.json"] = json.dumps(record).encode()
    raw = verify_raw(files)
    for name, blob in files.items():
        (tmp_path / name).write_bytes(blob)
    write(tmp_path / "raw_verification.json", raw)
    report = load_holdout(tmp_path)
    assert not report["errors"], report["errors"]
    assert report["aggregate"]["status"] == "aggregate_checked_only"
    assert any(r["metric"] == "completion_send" for r in report["rows"])
    assert report["runtime_execution_verified"] is False
    (tmp_path / "sweep_holdout_summary.csv").write_text("tampered", encoding="utf-8")
    assert load_holdout(tmp_path)["errors"]


@pytest.mark.parametrize("change", ["bytes", "path", "raw_hash"])
def test_figure_package_integrity_rejects_unsafe_or_changed_content(tmp_path, change):
    raw = package(tmp_path)
    name = "holdout_attack_tool_execution.png"
    directory = tmp_path / "figures"
    directory.mkdir()
    (directory / name).write_bytes(b"synthetic-test-image")
    hashes = {name: hashlib.sha256(b"synthetic-test-image").hexdigest()}
    raw["figure_sha256"] = hashes
    write(tmp_path / "raw_verification.json", raw)
    metadata = {
        "status": "raw_arithmetic_verified",
        "runtime_execution_verified": False,
        "figure_sha256": deepcopy(hashes),
        "input_sha256": raw["input_sha256"],
        "raw_verification_report_sha256": hashlib.sha256(
            (tmp_path / "raw_verification.json").read_bytes()
        ).hexdigest(),
    }
    write(directory / "aggregate_validation.json", metadata)
    assert load_holdout(tmp_path)["figures"] == [str(directory / name)]
    if change == "bytes":
        (directory / name).write_bytes(b"changed")
    elif change == "path":
        metadata["figure_sha256"]["../outside.png"] = "0" * 64
    elif change == "raw_hash":
        metadata["raw_verification_report_sha256"] = "0" * 64
    write(directory / "aggregate_validation.json", metadata)
    assert load_holdout(tmp_path)["errors"]


def test_tuning_audit_cannot_relabel_holdout_or_hide_mismatches(tmp_path):
    from demo.benchmark_reader import load_tuning

    data = payload()
    cells = []
    for row in data["sweep_default"]:
        cells.append(
            {**row, **{metric: row[source] for source, (metric, _) in METRICS.items()}}
        )
    audit = {
        "schema_version": "imported-fatin-audit-v1",
        "status": "arithmetic_audited",
        "evidence_validated": False,
        "split": "tune",
        "summary_mismatches": [],
        "cells": cells,
        "latency": [
            {"condition": "B", "n": 1, "mean_ms": 0.2, "p50_ms": 0.2, "p95_ms": 0.2}
        ],
    }
    write(tmp_path / "audit_summary.json", audit)
    assert load_tuning(tmp_path)["split"] == "tune"
    audit["split"] = "holdout"
    write(tmp_path / "audit_summary.json", audit)
    with pytest.raises(ValueError):
        load_tuning(tmp_path)
    audit["split"], audit["summary_mismatches"] = "tune", ["mismatch"]
    write(tmp_path / "audit_summary.json", audit)
    with pytest.raises(ValueError):
        load_tuning(tmp_path)
