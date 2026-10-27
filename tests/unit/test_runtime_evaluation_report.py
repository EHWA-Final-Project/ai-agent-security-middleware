"""Report contracts exercised with actual Runtime and SQLite, with graph rendering isolated."""

import csv
import json
from importlib import import_module
from pathlib import Path

import pytest

from evidence.sqlite_repository import SQLiteEvidenceRepository
from security.policy.conditions import load_condition


@pytest.fixture
def reporter(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]))
    module = import_module("scripts.run_runtime_evaluation")
    monkeypatch.setattr(module, "render_graphs", lambda *args: None)
    return module


def test_runtime_report_metadata_counts_and_saved_trials(tmp_path, reporter):
    output = tmp_path / "baseline"
    report = reporter.run_experiment(output, repeats=1, seed=17)
    assert report["status"] == "completed"
    assert report["source"] == "REAL MIDDLEWARE EXECUTION WITH MOCK TOOLS"
    experiment = report["experiment"]
    assert experiment["scenario_list"] == ["BENIGN-001", "ATTACK-001"]
    assert experiment["total_trials"] == 6
    assert experiment["seeds_per_scenario_per_mode"] == [17]
    assert experiment["distinct_attack_scenarios"] == 1
    assert experiment["repeats_per_scenario_per_mode"] == 1
    assert "Runtime end-to-end" in experiment["latency_scope"]
    assert "(n - 1) * p" in experiment["percentile_method"]
    assert "deterministic" in experiment["seed_scope"]
    assert experiment["strict_thresholds"] == {
        mode: load_condition(mode).policy.strict_threshold for mode in ("A", "B", "C")
    }
    for mode in ("A", "B", "C"):
        counts = report["sample_counts"][mode]
        assert counts["total_trials"] == counts["completed_trials"] == 2
        assert counts["asr_denominator"] == counts["tsr_denominator"] == counts["fpr_denominator"] == 1
        assert counts["block_rate_denominator"] == counts["latency_samples"] == 2
        assert report["metrics"][mode]["policy_version"] == load_condition(mode).policy.policy_version
        assert report["metrics"][mode]["asr"] == (1.0 if mode == "A" else 0.0)
        assert report["metrics"][mode]["tsr"] == 1.0
        assert report["metrics"][mode]["fpr"] == 0.0
        assert report["metrics"][mode]["block_rate"] == (0.0 if mode == "A" else 0.5)
    saved = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert saved == report
    with (output / "summary.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    assert [row["mode"] for row in rows] == ["A", "B", "C"]
    assert all(row["asr_denominator"] == "1" for row in rows)
    hashes = report["environment"]["source_sha256"]
    for source in (
        "src/evidence/sqlite_repository.py", "src/runtime/adapter.py",
        "src/runtime/runner.py", "src/security/orchestrator/orchestrator.py",
        "src/security/plugins/guards/input_guard.py",
    ):
        assert len(hashes[source]) == 64
    trials = json.loads((output / "trials.json").read_text(encoding="utf-8"))
    assert len(trials) == len({trial["run_id"] for trial in trials}) == 6
    assert len({trial["trace_id"] for trial in trials}) == 6
    repository = SQLiteEvidenceRepository(output / "evidence.sqlite3")
    for trial in trials:
        raw = trial["runtime_result"]
        assert raw["evidence_validated"] is True
        assert raw["run_status"] == "COMPLETED"
        assert raw["identity"]["run_id"] == trial["run_id"]
        assert raw["identity"]["trace_id"] == trial["trace_id"]
        assert raw["identity"]["scenario_id"] == trial["scenario_id"]
        assert raw["decision"]["policy_version"] == trial["policy_version"]
        assert trial["latency_ms"] >= 0
        events = repository.list_events_by_run(trial["run_id"])
        assert events
        assert {event.event_id for event in events} == {
            event.event_id for event in repository.list_events_by_trace(trial["trace_id"])
        }
    assert not (output / "failure.json").exists()


def test_threshold_demonstration_keeps_separate_samples_and_versions(tmp_path, reporter):
    baseline = reporter.run_experiment(tmp_path / "baseline", repeats=1)
    demo = reporter.run_experiment(tmp_path / "demonstration", repeats=1, block_threshold=0.92)
    assert baseline["experiment"]["purpose"] == "baseline"
    assert demo["experiment"]["purpose"] == "mechanism demonstration"
    assert baseline["experiment"]["block_threshold"] == 0.80
    assert demo["experiment"]["block_threshold"] == 0.92
    for mode in ("A", "B", "C"):
        assert baseline["metrics"][mode]["total_runs"] == demo["metrics"][mode]["total_runs"] == 2
        assert "+block0.92" not in baseline["metrics"][mode]["policy_version"]
        assert demo["metrics"][mode]["policy_version"].endswith("+block0.92")
    baseline_trials = json.loads((tmp_path / "baseline" / "trials.json").read_text(encoding="utf-8"))
    demo_trials = json.loads((tmp_path / "demonstration" / "trials.json").read_text(encoding="utf-8"))
    assert not {t["run_id"] for t in baseline_trials} & {t["run_id"] for t in demo_trials}


def test_existing_output_directory_is_preserved(tmp_path, reporter):
    output = tmp_path / "existing"
    output.mkdir()
    sentinel = output / "preserve.txt"
    sentinel.write_text("keep", encoding="utf-8")
    with pytest.raises(FileExistsError):
        reporter.run_experiment(output, repeats=1)
    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert not (output / "summary.json").exists()
    assert not (output / "failure.json").exists()


def test_failed_runtime_writes_diagnostic_without_success_metrics(tmp_path, reporter, monkeypatch):
    scenarios = reporter.load_runtime_scenarios()
    scenarios[0]["execution_payload"]["tool_candidate"]["args"]["path"] = "missing.txt"
    monkeypatch.setattr(reporter, "load_runtime_scenarios", lambda: scenarios)
    output = tmp_path / "failed-runtime"
    with pytest.raises(ValueError, match="did not complete"):
        reporter.run_experiment(output, repeats=1)
    failure = json.loads((output / "failure.json").read_text(encoding="utf-8"))
    assert failure["status"] == "failed"
    assert failure["runtime_trials"][0]["run_status"] == "FAILED"
    assert failure["runtime_trials"][0]["evidence_validated"] is False
    assert not (output / "summary.json").exists()
    assert not (output / "summary.csv").exists()


def test_graph_failure_does_not_emit_success_summary(tmp_path, reporter, monkeypatch):
    def fail_graphs(*args):
        raise RuntimeError("graph render failure")

    monkeypatch.setattr(reporter, "render_graphs", fail_graphs)
    output = tmp_path / "failed-graphs"
    with pytest.raises(RuntimeError, match="graph render failure"):
        reporter.run_experiment(output, repeats=1)
    failure = json.loads((output / "failure.json").read_text(encoding="utf-8"))
    assert failure["status"] == "failed"
    assert len(failure["runtime_trials"]) == 6
    assert (output / "trials.json").exists()
    assert not (output / "summary.json").exists()
    assert not (output / "summary.csv").exists()


@pytest.mark.parametrize("kwargs", [{"repeats": 0}, {"block_threshold": 0.7}])
def test_invalid_experiment_config_has_no_outputs(tmp_path, reporter, kwargs):
    output = tmp_path / "invalid-config"
    with pytest.raises(ValueError):
        reporter.run_experiment(output, **kwargs)
    assert not output.exists()
