"""Focused offline raw-verification regressions using small synthetic evidence."""

import hashlib
import json

import pytest

from scripts.plot_holdout_aggregates import THRESHOLDS, parse_csv
from scripts.verify_holdout_raw import (
    canonical,
    generate,
    guard_metrics,
    recalculate_causes,
    validate_trials,
    verify_raw,
)
from tests.unit.test_plot_holdout_aggregates import _csv, _update_hash, _write_zip


def fixture_files():
    trials, summaries = [], []
    for condition, threshold in [("A", None)] + [
        (c, t) for c in ("B", "C") for t in THRESHOLDS
    ]:
        guarded = condition != "A"
        for kind, ids in (
            ("direct", ["d0", "d1"]),
            ("indirect", ["i0", "i1"]),
            ("benign_read", ["b"]),
            ("benign_send", ["b"]),
        ):
            for index, identity in enumerate(ids):
                blocked = guarded and index == 0 and kind in {"direct", "indirect"}
                warned = guarded and kind.startswith("benign")
                trials.append(
                    {
                        "condition": condition,
                        "threshold": threshold,
                        "sample_id": identity,
                        "trial_type": kind,
                        "source": "synthetic",
                        "final_risk": 1 if blocked else 0,
                        "decision": "BLOCK"
                        if blocked
                        else ("WARN" if warned else "ALLOW"),
                        "tool_executed": int(not blocked),
                        "output_allowed": int(not blocked and not warned),
                        "block_stage": "pre_tool" if blocked else "",
                        "block_cause": "cumulative_risk" if blocked else "",
                        "input_score": 1 if blocked else 0,
                        "context_score": "",
                        "tool_score": "",
                        "output_score": "",
                    }
                )
        summaries.append(
            {
                "condition": condition,
                "threshold": threshold,
                "n_attack": 4,
                "n_benign_read": 1,
                "n_benign_send": 1,
                "ASR": 0.5 if guarded else 1,
                "ASR_direct": 0.5 if guarded else 1,
                "ASR_indirect": 0.5 if guarded else 1,
                "pre_tool_block": 0.5 if guarded else 0,
                "FPR_read(WARN|BLOCK)": int(guarded),
                "FPR_read(BLOCK)": 0,
                "TSR_read": int(not guarded),
                "FPR_send(WARN|BLOCK)": int(guarded),
                "FPR_send(BLOCK)": 0,
            }
        )
    causes = [
        {
            "threshold": t,
            "n_attack": 4,
            "n_pre_tool_block": 2,
            "cumulative_risk": 2,
            "strict_warn_escalation": 0,
            "guard_block_or_other": 0,
            "single_guard_ge_thr": 2,
            "cause_source": "block_cause",
        }
        for t in THRESHOLDS
    ]
    guards = [
        {
            "sample_id": identity,
            "dataset": "synthetic",
            "subset": "all",
            "label": "benign" if identity == "b" else "attack",
            "guard": "input",
            "split": "holdout",
            "risk_score": 0.5,
            "decision": "WARN",
        }
        for identity in ["b", "d0", "d1", "i0", "i1"]
    ]
    data = {"samples_sha256": "synthetic", "n_samples_in_split": 5}
    results = {
        "kind": "benchmark_evaluation",
        "split": "holdout",
        "run": {"core_commit": "synthetic"},
        "data": data,
        "sweep_default": summaries,
        "sweep_with_tool_policy": summaries,
        "c_block_cause": causes,
    }
    files = {
        "holdout_results.json": json.dumps(results).encode(),
        "sweep_holdout_summary.csv": _csv(summaries),
        "sweep_policy_holdout_summary.csv": _csv(summaries),
        "c_cause_holdout.csv": _csv(causes),
        "sweep_holdout_trials.csv": _csv(trials),
        "sweep_policy_holdout_trials.csv": _csv(trials),
        "guards_holdout.csv": _csv(guards),
    }
    record = {
        "split": "holdout",
        "core_commit": "synthetic",
        "data": dict(
            data,
            split_sample_ids_sha256=hashlib.sha256(b"b\nd0\nd1\ni0\ni1").hexdigest(),
        ),
        "policy": {"strict_threshold_default": 0.5},
        "output_sha256": {
            n: hashlib.sha256(b).hexdigest()
            for n, b in files.items()
            if n.endswith(".csv")
        },
    }
    files["run_record_holdout.json"] = json.dumps(record).encode()
    return files


def change_raw(files, name, mutate):
    rows = parse_csv(files[name])
    mutate(rows)
    files[name] = _csv(rows)
    _update_hash(files, name)


def test_full_audit_counts_rates_causes_and_population():
    report = verify_raw(fixture_files())
    assert report["status"] == "raw_arithmetic_verified"
    assert not any(report["mismatch_totals"].values())
    assert report["runtime_execution_verified"] is False
    sweep = report["sweeps"]["default"]
    assert (sweep["rows"], sweep["conditions"], sweep["unique_sample_ids"]) == (
        102,
        17,
        5,
    )
    cell = sweep["cells"][1]
    assert cell["attack_tool_execution_numerator"] == 2
    assert cell["pre_tool_block_numerator"] == 2
    assert cell["completion_read"] == 0  # executed but WARN withheld output
    assert cell["fpr_read_warn_only"] == 1
    assert report["guards"]["false_positive_ids"] == ["b"]
    assert report["population_mapping"]["scenario_trials_per_condition"] == 6


@pytest.mark.parametrize(
    "name",
    [
        "sweep_holdout_trials.csv",
        "sweep_policy_holdout_trials.csv",
        "guards_holdout.csv",
    ],
)
def test_raw_hash_tampering_rejected(name):
    files = fixture_files()
    files[name] += b"\n"
    with pytest.raises(ValueError, match="SHA256"):
        verify_raw(files)


def test_raw_metric_disagreement_is_reported_against_csv_and_json():
    files = fixture_files()

    def mutate(rows):
        rows[6].update(
            decision="ALLOW",
            tool_executed="1",
            output_allowed="1",
            block_stage="",
            block_cause="",
        )

    change_raw(files, "sweep_policy_holdout_trials.csv", mutate)
    report = verify_raw(files)
    assert report["status"] == "mismatches_found"
    assert report["mismatch_totals"]["summary_csv"] == 3
    assert report["mismatch_totals"]["summary_json"] == 3


def test_cause_disagreement_is_independent_of_summary_metrics():
    files = fixture_files()

    def mutate(rows):
        next(r for r in rows if r["condition"] == "C" and r["block_cause"])[
            "block_cause"
        ] = "strict_warn_escalation"

    change_raw(files, "sweep_holdout_trials.csv", mutate)
    report = verify_raw(files)
    assert report["mismatch_totals"]["summary_csv"] == 0
    assert report["mismatch_totals"]["causes_csv"] == 2
    assert report["mismatch_totals"]["causes_json"] == 2


def test_single_guard_uses_individual_scores_not_cumulative_risk():
    rows = canonical(parse_csv(fixture_files()["sweep_holdout_trials.csv"]))
    for row in rows:
        row["input_score"] = "0.4"
        row["context_score"] = "0.4"
    causes = recalculate_causes(rows)
    assert causes[0]["cumulative_risk"] == 2
    assert causes[0]["single_guard_ge_thr"] == 0


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate",
        "unknown_type",
        "missing_cause",
        "bad_flag",
        "wrong_split",
        "population",
    ],
)
def test_invalid_raw_records_fail_closed(mutation):
    files = fixture_files()

    def mutate(rows):
        if mutation == "duplicate":
            rows.append(dict(rows[0]))
        elif mutation == "unknown_type":
            rows[0]["trial_type"] = "unknown"
        elif mutation == "missing_cause":
            rows[6]["block_cause"] = ""
        elif mutation == "bad_flag":
            rows[0]["tool_executed"] = "yes"
        elif mutation == "wrong_split":
            for row in rows:
                row["split"] = "tune"
        else:
            rows.pop()

    change_raw(files, "sweep_holdout_trials.csv", mutate)
    with pytest.raises(ValueError):
        verify_raw(files)


@pytest.mark.parametrize("mutation", ["duplicate", "split", "nan", "decision"])
def test_invalid_guards_rejected(mutation):
    rows = parse_csv(fixture_files()["guards_holdout.csv"])
    if mutation == "duplicate":
        rows.append(dict(rows[0]))
    else:
        field, value = {
            "split": ("split", "tune"),
            "nan": ("risk_score", "nan"),
            "decision": ("decision", "ALLOW"),
        }[mutation]
        rows[0][field] = value
    with pytest.raises(ValueError):
        guard_metrics(rows, 0.5)


def test_guard_identity_hash_mismatch_reported():
    files = fixture_files()
    record = json.loads(files["run_record_holdout.json"])
    record["data"]["split_sample_ids_sha256"] = "wrong"
    files["run_record_holdout.json"] = json.dumps(record).encode()
    assert verify_raw(files)["mismatch_totals"]["guard_metadata"] == 1


def test_missing_raw_files_and_empty_trials_rejected():
    files = fixture_files()
    del files["guards_holdout.csv"]
    with pytest.raises(ValueError, match="Missing raw"):
        verify_raw(files)
    with pytest.raises(ValueError, match="Empty trials"):
        validate_trials([])


def test_generate_reproducible_report_preserves_inputs_and_outputs(tmp_path):
    files = fixture_files()
    source = tmp_path / "source.zip"
    _write_zip(source, files)
    raw = tmp_path / "raw"
    raw.mkdir()
    for name in (
        "sweep_holdout_trials.csv",
        "sweep_policy_holdout_trials.csv",
        "guards_holdout.csv",
    ):
        (raw / name).write_bytes(files[name])
    first, second = tmp_path / "first", tmp_path / "second"
    report = generate(source, raw, first)
    assert generate(source, raw, second) == report
    assert (first / "raw_verification.json").read_bytes() == (
        second / "raw_verification.json"
    ).read_bytes()
    checked = generate(source, raw, tmp_path / "checked", first / "figures")
    assert checked["existing_figure_byte_mismatches"] == []
    assert len(checked["figure_sha256"]) == 8
    with pytest.raises(FileExistsError):
        generate(source, raw, first)
    assert all(path.read_bytes() == files[path.name] for path in raw.iterdir())


def test_final_metadata_hashes_actual_report_bytes_and_packages_reproducibly(tmp_path):
    import zipfile

    from scripts.verify_holdout_raw import package_outputs

    files = fixture_files()
    source = tmp_path / "source.zip"
    _write_zip(source, files)
    raw = tmp_path / "raw"
    raw.mkdir()
    for name in (
        "sweep_holdout_trials.csv",
        "sweep_policy_holdout_trials.csv",
        "guards_holdout.csv",
    ):
        (raw / name).write_bytes(files[name])
    first, second = tmp_path / "first", tmp_path / "second"
    report = generate(source, raw, first)
    assert generate(source, raw, second) == report
    raw_bytes = (first / "raw_verification.json").read_bytes()
    audit_path = first / "figures/aggregate_validation.json"
    audit = json.loads(audit_path.read_bytes())
    assert (audit_path.parent / audit["raw_verification_report"]).resolve() == (
        first / "raw_verification.json"
    ).resolve()
    assert (
        audit["raw_verification_report_sha256"] == hashlib.sha256(raw_bytes).hexdigest()
    )
    assert audit["raw_verification_hash_scope"] == "exact_file_bytes"
    assert audit["status"] == audit["figure_verification_status"] == report["status"]
    assert audit["status"] == "raw_arithmetic_verified"
    assert audit["raw_trial_recalculation_performed"] is True
    assert audit["runtime_execution_verified"] is False
    assert audit["missing_raw_files"] == []
    assert audit["limitations"] == report["limitations"]
    assert audit["input_sha256"] == report["input_sha256"]
    assert "raw_verification_report_sha256" not in report
    assert not (first / "figures/raw_verification.json").exists()
    for output in (first, second):
        package_outputs(output, output.with_suffix(".zip"))
    assert (
        first.with_suffix(".zip").read_bytes()
        == second.with_suffix(".zip").read_bytes()
    )
    with zipfile.ZipFile(first.with_suffix(".zip")) as archive:
        assert len(archive.namelist()) == 10
        assert archive.read("raw_verification.json") == raw_bytes
        assert (
            archive.read("figures/aggregate_validation.json") == audit_path.read_bytes()
        )
        for name, digest in report["figure_sha256"].items():
            assert hashlib.sha256(archive.read("figures/" + name)).hexdigest() == digest
    # Even whitespace changes break the exact-file reference; stale packages fail closed.
    (first / "raw_verification.json").write_bytes(raw_bytes + b"\n")
    with pytest.raises(ValueError, match="metadata"):
        package_outputs(first, tmp_path / "stale.zip")
    assert not (tmp_path / "stale.zip").exists()
    (first / "raw_verification.json").write_bytes(raw_bytes)
    original_audit = audit_path.read_bytes()
    for field, value in (
        ("raw_verification_report", "../stale.json"),
        ("status", "aggregate_checked_only"),
        ("runtime_execution_verified", True),
    ):
        altered = dict(audit, **{field: value})
        audit_path.write_text(json.dumps(altered), encoding="utf-8")
        with pytest.raises(ValueError, match="metadata"):
            package_outputs(first, tmp_path / "rejected.zip")
        assert not (tmp_path / "rejected.zip").exists()
    audit_path.write_bytes(original_audit)
    image = next((first / "figures").glob("*.png"))
    image.write_bytes(image.read_bytes() + b"tampered")
    with pytest.raises(ValueError, match="Figure hash mismatch"):
        package_outputs(first, tmp_path / "tampered.zip")
    assert not (tmp_path / "tampered.zip").exists()


def test_failed_raw_verification_writes_no_verified_metadata_or_package(tmp_path):
    from scripts.verify_holdout_raw import package_outputs

    files = fixture_files()

    def mutate(rows):
        rows[6].update(
            decision="ALLOW",
            tool_executed="1",
            output_allowed="1",
            block_stage="",
            block_cause="",
        )

    change_raw(files, "sweep_policy_holdout_trials.csv", mutate)
    source = tmp_path / "bad.zip"
    _write_zip(source, files)
    for name in (
        "sweep_holdout_trials.csv",
        "sweep_policy_holdout_trials.csv",
        "guards_holdout.csv",
    ):
        (tmp_path / name).write_bytes(files[name])
    output = tmp_path / "failed"
    assert generate(source, tmp_path, output)["status"] == "mismatches_found"
    assert not (output / "figures/aggregate_validation.json").exists()
    assert not list(output.rglob("*.png"))
    with pytest.raises((ValueError, FileNotFoundError)):
        package_outputs(output, tmp_path / "failed_package.zip")
    assert not (tmp_path / "failed_package.zip").exists()
