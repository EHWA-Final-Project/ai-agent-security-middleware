"""Offline aggregate checks and rendering regressions; no dataset files needed."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile

import pytest

from scripts.plot_holdout_aggregates import generate, load_files, parse_csv, verify

THRESHOLDS = [0.7, 0.75, 0.8, 0.85, 0.9, 0.92, 0.95, 0.98]
TABLES = {
    "sweep_holdout_summary.csv": "sweep_default",
    "sweep_policy_holdout_summary.csv": "sweep_with_tool_policy",
    "c_cause_holdout.csv": "c_block_cause",
}


def _csv(rows):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode()


def _fixture_files():
    base = {
        "n_attack": 10,
        "n_benign_read": 4,
        "FPR_read(WARN|BLOCK)": 0.0,
        "FPR_read(BLOCK)": 0.0,
        "TSR_read": 1.0,
        "n_benign_send": 3,
        "FPR_send(WARN|BLOCK)": 1.0,
        "FPR_send(BLOCK)": 0.0,
    }

    def row(condition, threshold):
        asr = 1.0 if condition == "A" else (0.8 if condition == "B" else 0.5)
        return {
            "condition": condition,
            "threshold": threshold,
            **base,
            "ASR": asr,
            "ASR_indirect": asr,
            "ASR_direct": asr,
            "pre_tool_block": 1 - asr,
        }

    main = [row("A", None)] + [
        row(condition, threshold)
        for condition in ("B", "C")
        for threshold in THRESHOLDS
    ]
    main[0]["FPR_send(WARN|BLOCK)"] = 0.0
    policy = [
        dict(r, ASR=0.0, ASR_direct=0.0, ASR_indirect=0.0, pre_tool_block=1.0)
        if r["condition"] != "A"
        else dict(r)
        for r in main
    ]
    causes = [
        {
            "threshold": threshold,
            "n_attack": 10,
            "n_pre_tool_block": 5,
            "cumulative_risk": 5,
            "strict_warn_escalation": 0,
            "guard_block_or_other": 0,
            "single_guard_ge_thr": 2,
            "cause_source": "block_cause",
        }
        for threshold in THRESHOLDS
    ]
    results = {
        "kind": "benchmark_evaluation",
        "split": "holdout",
        "run": {"core_commit": "deadbeef"},
        "data": {"samples_sha256": "datahash", "n_samples_in_split": 12},
        "sweep_default": main,
        "sweep_with_tool_policy": policy,
        "c_block_cause": causes,
    }
    files = {
        "sweep_holdout_summary.csv": _csv(main),
        "sweep_policy_holdout_summary.csv": _csv(policy),
        "c_cause_holdout.csv": _csv(causes),
        "holdout_results.json": json.dumps(results).encode(),
    }
    record = {
        "split": "holdout",
        "core_commit": "deadbeef",
        "code_dirty": False,
        "data": {"samples_sha256": "datahash", "n_samples_in_split": 12},
        "output_sha256": {
            name: hashlib.sha256(blob).hexdigest()
            for name, blob in files.items()
            if name.endswith(".csv")
        },
    }
    files["run_record_holdout.json"] = json.dumps(record).encode()
    return files


def _update_hash(files, name):
    record = json.loads(files["run_record_holdout.json"])
    record["output_sha256"][name] = hashlib.sha256(files[name]).hexdigest()
    files["run_record_holdout.json"] = json.dumps(record).encode()


def _replace_table(files, name, rows, *, update_json=True):
    files[name] = _csv(rows)
    _update_hash(files, name)
    if update_json:
        results = json.loads(files["holdout_results.json"])
        results[TABLES[name]] = rows
        files["holdout_results.json"] = json.dumps(results).encode()


def _json_rows(files, name):
    return json.loads(files["holdout_results.json"])[TABLES[name]]


def _write_zip(path, files):
    with zipfile.ZipFile(path, "w") as archive:
        for name, blob in files.items():
            archive.writestr(f"for-wana/{name}", blob)


def test_synthetic_summaries_verify_without_raw_trials():
    _, summary, policy, causes, audit = verify(_fixture_files())
    assert len(summary) == len(policy) == 17
    assert len(causes) == 8
    assert audit["status"] == "aggregate_checked_only"
    assert audit["raw_trial_recalculation_performed"] is False
    assert set(audit["missing_raw_files"]) == {
        "sweep_holdout_trials.csv",
        "sweep_policy_holdout_trials.csv",
        "guards_holdout.csv",
    }


def test_optional_raw_presence_does_not_claim_raw_verification():
    files = _fixture_files()
    # Deliberately opaque: this command must never claim to audit raw evidence.
    for name in (
        "sweep_holdout_trials.csv",
        "sweep_policy_holdout_trials.csv",
        "guards_holdout.csv",
    ):
        files[name] = b"synthetic optional data\n"
        _update_hash(files, name)
    audit = verify(files)[-1]
    assert audit["status"] == "aggregate_checked_only"
    assert audit["raw_trial_recalculation_performed"] is False
    assert audit["missing_raw_files"] == []


@pytest.mark.parametrize("name", list(TABLES))
def test_tampered_csv_fails_sha_verification(name):
    files = _fixture_files()
    files[name] += b"\n"
    with pytest.raises(ValueError, match="SHA256 mismatch"):
        verify(files)


@pytest.mark.parametrize(
    "name", [*TABLES, "holdout_results.json", "run_record_holdout.json"]
)
def test_missing_required_file_rejected(name):
    files = _fixture_files()
    del files[name]
    with pytest.raises(ValueError):
        verify(files)


def test_missing_recorded_csv_hash_rejected():
    files = _fixture_files()
    record = json.loads(files["run_record_holdout.json"])
    del record["output_sha256"]["sweep_holdout_summary.csv"]
    files["run_record_holdout.json"] = json.dumps(record).encode()
    with pytest.raises(ValueError):
        verify(files)


@pytest.mark.parametrize("name", list(TABLES))
def test_csv_json_disagreement_rejected_after_hash_update(name):
    files = _fixture_files()
    rows = _json_rows(files, name)
    field = "cumulative_risk" if name == "c_cause_holdout.csv" else "n_attack"
    rows[0][field] += 1
    _replace_table(files, name, rows, update_json=False)
    with pytest.raises(ValueError):
        verify(files)


@pytest.mark.parametrize("name", list(TABLES))
def test_matching_tables_with_missing_required_column_rejected(name):
    files = _fixture_files()
    rows = _json_rows(files, name)
    field = "cause_source" if name == "c_cause_holdout.csv" else "ASR_direct"
    for row in rows:
        del row[field]
    _replace_table(files, name, rows)
    with pytest.raises(ValueError):
        verify(files)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -0.1, 1.1])
def test_nonfinite_or_out_of_bounds_rate_rejected(value):
    files = _fixture_files()
    rows = _json_rows(files, "sweep_holdout_summary.csv")
    rows[1]["ASR_direct"] = value
    _replace_table(files, "sweep_holdout_summary.csv", rows)
    with pytest.raises(ValueError):
        verify(files)


@pytest.mark.parametrize("value", [0, -1, 10.5, float("inf")])
def test_invalid_trial_denominator_rejected(value):
    files = _fixture_files()
    rows = _json_rows(files, "sweep_holdout_summary.csv")
    rows[1]["n_attack"] = value
    _replace_table(files, "sweep_holdout_summary.csv", rows)
    with pytest.raises(ValueError):
        verify(files)


def test_rate_incompatible_with_integer_count_rejected():
    files = _fixture_files()
    rows = _json_rows(files, "sweep_holdout_summary.csv")
    rows[1]["ASR"] = 0.81
    rows[1]["ASR_direct"] = 0.81
    rows[1]["ASR_indirect"] = 0.81
    rows[1]["pre_tool_block"] = 0.19
    _replace_table(files, "sweep_holdout_summary.csv", rows)
    with pytest.raises(ValueError, match="integer count"):
        verify(files)


def test_attack_execution_and_pretool_block_must_sum_to_one():
    files = _fixture_files()
    rows = _json_rows(files, "sweep_holdout_summary.csv")
    rows[1]["pre_tool_block"] = 0.3
    _replace_table(files, "sweep_holdout_summary.csv", rows)
    with pytest.raises(ValueError):
        verify(files)


@pytest.mark.parametrize("name", list(TABLES))
@pytest.mark.parametrize("change", ["missing", "duplicate", "wrong_threshold"])
def test_invalid_threshold_grid_rejected(name, change):
    files = _fixture_files()
    rows = _json_rows(files, name)
    if change == "missing":
        rows.pop()
    elif change == "duplicate":
        rows[-1] = dict(rows[-2])
    else:
        rows[-1]["threshold"] = 0.99
    _replace_table(files, name, rows)
    with pytest.raises(ValueError):
        verify(files)


def test_baseline_must_have_null_threshold():
    files = _fixture_files()
    rows = _json_rows(files, "sweep_holdout_summary.csv")
    rows[0]["threshold"] = 0.7
    _replace_table(files, "sweep_holdout_summary.csv", rows)
    with pytest.raises(ValueError):
        verify(files)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("cumulative_risk", 4),
        ("single_guard_ge_thr", 1),
        ("strict_warn_escalation", -1),
        ("cumulative_risk", 4.5),
        ("n_attack", 20),
    ],
)
def test_invalid_cause_counts_rejected_even_if_both_tables_match(field, value):
    files = _fixture_files()
    rows = _json_rows(files, "c_cause_holdout.csv")
    rows[0][field] = value
    _replace_table(files, "c_cause_holdout.csv", rows)
    with pytest.raises(ValueError):
        verify(files)


def test_cause_total_must_match_default_c_block_rate():
    files = _fixture_files()
    rows = _json_rows(files, "c_cause_holdout.csv")
    rows[0]["n_pre_tool_block"] = 4
    rows[0]["cumulative_risk"] = 4
    _replace_table(files, "c_cause_holdout.csv", rows)
    with pytest.raises(ValueError):
        verify(files)


@pytest.mark.parametrize("field", ["split", "core_commit", "samples_sha256"])
def test_conflicting_run_metadata_rejected(field):
    files = _fixture_files()
    record = json.loads(files["run_record_holdout.json"])
    if field == "samples_sha256":
        record["data"][field] = "another-datahash"
    else:
        record[field] = "different"
    files["run_record_holdout.json"] = json.dumps(record).encode()
    with pytest.raises(ValueError):
        verify(files)


def test_consistent_tuning_label_rejected():
    files = _fixture_files()
    for name in ("holdout_results.json", "run_record_holdout.json"):
        document = json.loads(files[name])
        document["split"] = "tune"
        files[name] = json.dumps(document).encode()
    with pytest.raises(ValueError):
        verify(files)


def test_csv_bom_and_crlf_are_supported():
    assert parse_csv(b"\xef\xbb\xbfcondition,threshold\r\nA,\r\n") == [
        {"condition": "A", "threshold": ""}
    ]


@pytest.mark.parametrize(
    "blob",
    [b"x,x\n1,2\n", b",x\n1,2\n", b"x,y\n1\n", b"x,y\n1,2,3\n", b""],
    ids=["duplicate-header", "empty-header", "short-row", "long-row", "empty-file"],
)
def test_malformed_csv_structure_rejected(blob):
    with pytest.raises(ValueError):
        parse_csv(blob)


@pytest.mark.parametrize("name", ["holdout_results.json", "run_record_holdout.json"])
def test_duplicate_json_keys_rejected(name):
    files = _fixture_files()
    files[name] = files[name].replace(
        b'"split": "holdout"', b'"split": "holdout", "split": "holdout"', 1
    )
    with pytest.raises(ValueError):
        verify(files)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_json_metadata_rejected(value):
    files = _fixture_files()
    record = json.loads(files["run_record_holdout.json"])
    record["metadata"] = {"elapsed_seconds": value}
    files["run_record_holdout.json"] = json.dumps(record).encode()
    with pytest.raises(ValueError):
        verify(files)


@pytest.mark.parametrize("conflict", [None, "tool_policy", "headline_block_threshold"])
def test_policy_metadata_must_agree(conflict):
    files = _fixture_files()
    results = json.loads(files["holdout_results.json"])
    record = json.loads(files["run_record_holdout.json"])
    results["tool_policy"] = {"allowed_tools": ["read_file"]}
    results["headline_block_threshold"] = 0.8
    record["policy"] = {
        "tool_policy_policy_run": {"allowed_tools": ["read_file"]},
        "headline_block_threshold": 0.8,
        "threshold_sweep": THRESHOLDS,
        "conditions": ["A", "B", "C"],
    }
    if conflict == "tool_policy":
        results[conflict] = {"allowed_tools": ["send_email"]}
    elif conflict == "headline_block_threshold":
        results[conflict] = 0.9
    files["holdout_results.json"] = json.dumps(results).encode()
    files["run_record_holdout.json"] = json.dumps(record).encode()
    if conflict:
        with pytest.raises(ValueError):
            verify(files)
    else:
        assert verify(files)[-1]["status"] == "aggregate_checked_only"


def test_duplicate_named_zip_members_rejected(tmp_path):
    path = tmp_path / "ambiguous.zip"
    files = _fixture_files()
    _write_zip(path, files)
    with zipfile.ZipFile(path, "a") as archive:
        archive.writestr("other/holdout_results.json", files["holdout_results.json"])
    with pytest.raises(ValueError, match="duplicate"):
        load_files(path)


def test_extracted_directory_is_supported(tmp_path):
    files = _fixture_files()
    extracted = tmp_path / "for-wana"
    extracted.mkdir()
    for name, blob in files.items():
        (extracted / name).write_bytes(blob)
    assert load_files(tmp_path) == files
    assert load_files(extracted) == files


def test_generate_reproducible_png_svg_json_and_protect_existing_output(tmp_path):
    zip_path = tmp_path / "fixture.zip"
    _write_zip(zip_path, _fixture_files())
    out = tmp_path / "new_graphs"
    report = generate(zip_path, out)
    assert report["status"] == "aggregate_checked_only"
    assert report["raw_trial_recalculation_performed"] is False
    assert len(list(out.glob("*.png"))) == 4
    assert len(list(out.glob("*.svg"))) == 4
    assert json.loads((out / "aggregate_validation.json").read_text()) == report
    before = {path.name: path.read_bytes() for path in out.iterdir()}
    second = tmp_path / "second_graphs"
    assert generate(zip_path, second) == report
    assert {path.name: path.read_bytes() for path in second.iterdir()} == before
    with pytest.raises(FileExistsError):
        generate(zip_path, out)
    assert {path.name: path.read_bytes() for path in out.iterdir()} == before


def test_failed_verification_does_not_create_output(tmp_path):
    files = _fixture_files()
    files["sweep_holdout_summary.csv"] += b"tampered"
    path = tmp_path / "invalid.zip"
    _write_zip(path, files)
    out = tmp_path / "graphs"
    with pytest.raises(ValueError):
        generate(path, out)
    assert not out.exists()


def test_raw_verified_footer_is_bound_to_matching_inputs(tmp_path):
    from scripts.plot_holdout_aggregates import RAW_LABEL
    from scripts.verify_holdout_raw import verify_raw
    from tests.unit.test_verify_holdout_raw import fixture_files

    files = fixture_files()
    report = verify_raw(files)
    source = tmp_path / "source.zip"
    _write_zip(source, files)
    audit = generate(source, tmp_path / "verified", raw_verification=report)
    assert audit["figure_label"] == RAW_LABEL
    assert audit["figure_verification_status"] == "raw_arithmetic_verified"
    assert audit["status"] == "raw_arithmetic_verified"
    assert audit["aggregate_stage"]["status"] == "aggregate_checked_only"
    packaged = tmp_path / "verified" / audit["raw_verification_report"]
    assert (
        audit["raw_verification_report_sha256"]
        == hashlib.sha256(packaged.read_bytes()).hexdigest()
    )
    for path in (tmp_path / "verified").glob("*.svg"):
        assert RAW_LABEL in path.read_text(encoding="utf-8")
        assert "not independently verified against raw trials" not in path.read_text(
            encoding="utf-8"
        )
    attack = (tmp_path / "verified/holdout_attack_tool_execution.svg").read_text(
        encoding="utf-8"
    )
    assert "Direct attacks · n=2" in attack
    fallback = generate(source, tmp_path / "aggregate")
    assert fallback["figure_verification_status"] == "aggregate_checked_only"
    assert "not independently verified against raw trials" in fallback["figure_label"]


@pytest.mark.parametrize(
    "damage",
    [
        "status",
        "mismatch",
        "hash",
        "missing_hash",
        "runtime",
        "cells",
        "denominator",
        "causes",
    ],
)
def test_invalid_raw_report_cannot_label_figures_verified(tmp_path, damage):
    from scripts.verify_holdout_raw import verify_raw
    from tests.unit.test_verify_holdout_raw import fixture_files

    files = fixture_files()
    report = verify_raw(files)
    if damage == "status":
        report["status"] = "mismatches_found"
    elif damage == "mismatch":
        report["mismatch_totals"]["summary_csv"] = 1
    elif damage == "hash":
        report["input_sha256"]["sweep_holdout_trials.csv"] = "wrong"
    elif damage == "missing_hash":
        del report["input_sha256"]["guards_holdout.csv"]
    elif damage == "runtime":
        report["runtime_execution_verified"] = True
    elif damage == "cells":
        report["sweeps"]["default"]["cells"][1]["attack_tool_execution"] = 0.25
    elif damage == "denominator":
        report["sweeps"]["default"]["cells"][0][
            "attack_tool_execution_direct_denominator"
        ] = 3
    else:
        report["c_causes"][0]["cumulative_risk"] += 1
    source = tmp_path / "source.zip"
    _write_zip(source, files)
    with pytest.raises(ValueError):
        generate(source, tmp_path / "invalid", raw_verification=report)
    assert not (tmp_path / "invalid").exists()


def test_plot_artists_preserve_metrics_thresholds_and_cause_totals(
    tmp_path, monkeypatch
):
    import matplotlib.figure

    from scripts.plot_holdout_aggregates import MODE_COLORS, THRESHOLDS, _render
    from scripts.verify_holdout_raw import verify_raw
    from tests.unit.test_verify_holdout_raw import fixture_files

    files = fixture_files()
    _, summary, policy, causes, _ = verify(files)
    report = verify_raw(files)
    saved = {}

    def capture(fig, path, **kwargs):
        saved[path.stem] = fig

    monkeypatch.setattr(matplotlib.figure.Figure, "savefig", capture)
    _render(tmp_path, summary, policy, causes, raw_report=report)
    attack = saved["holdout_attack_tool_execution"]
    assert tuple(attack.get_size_inches()) == (16, 9)
    for ax, field in zip(attack.axes, ("ASR", "ASR_direct", "ASR_indirect")):
        for index, mode in enumerate(("B", "C")):
            line = ax.lines[index]
            assert list(line.get_xdata()) == list(THRESHOLDS)
            assert list(line.get_ydata()) == [
                float(r[field]) for r in summary if r["condition"] == mode
            ]
            assert line.get_color() == MODE_COLORS[mode]
        assert ax.get_ylim()[0] <= 0 and ax.get_ylim()[1] >= 1
    benign = saved["holdout_benign_outcomes"]
    for row_index, rows in enumerate((summary, policy)):
        for col, kind in enumerate(("read", "send")):
            ax = benign.axes[row_index * 3 + col]
            for index, (mode, suffix) in enumerate(
                (
                    ("B", "WARN|BLOCK"),
                    ("B", "BLOCK"),
                    ("C", "WARN|BLOCK"),
                    ("C", "BLOCK"),
                )
            ):
                assert list(ax.lines[index].get_ydata()) == [
                    float(r[f"FPR_{kind}({suffix})"])
                    for r in rows
                    if r["condition"] == mode
                ]
    ax = saved["holdout_c_block_causes"].axes[0]
    bars = ax.containers
    assert [sum(bars[j][i].get_height() for j in range(3)) for i in range(8)] == [
        int(r["n_pre_tool_block"]) for r in causes
    ]
    assert list(ax.lines[0].get_ydata()) == [
        int(r["single_guard_ge_thr"]) for r in causes
    ]


def test_report_aware_cli_works_without_pytest_pythonpath(tmp_path):
    import os
    import subprocess
    import sys
    from pathlib import Path

    from scripts.verify_holdout_raw import verify_raw
    from tests.unit.test_verify_holdout_raw import fixture_files

    files = fixture_files()
    source = tmp_path / "source.zip"
    _write_zip(source, files)
    report_path = tmp_path / "raw_verification.json"
    report_path.write_text(json.dumps(verify_raw(files)), encoding="utf-8")
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.plot_holdout_aggregates",
            "--source",
            str(source),
            "--raw-verification",
            str(report_path),
            "--output",
            str(tmp_path / "figures"),
        ],
        cwd=Path(__file__).resolve().parents[2],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "Raw-trial aggregation verified" in result.stdout
