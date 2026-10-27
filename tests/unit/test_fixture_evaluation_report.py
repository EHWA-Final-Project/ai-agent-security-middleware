import csv
import json
from importlib import import_module
from pathlib import Path


def test_fixture_report_exports_metadata_and_metrics(
    tmp_path,
    monkeypatch,
):
    
    project_root = Path(__file__).resolve().parents[2]
    monkeypatch.syspath_prepend(str(project_root))

    fixture_demo = import_module("scripts.run_fixture_evaluation")

    monkeypatch.setattr(fixture_demo, "OUTPUT_DIR", tmp_path)

    fixture_demo.main()

    json_path = tmp_path / "fixture_bc_report.json"
    csv_path = tmp_path / "fixture_bc_metrics.csv"

    assert json_path.exists()
    assert csv_path.exists()

    report = json.loads(json_path.read_text(encoding="utf-8"))

    assert report["source"] == "FIXTURE / MOCK"
    assert report["experiment"]["total_trials"] == 12
    assert report["experiment"]["seed"] == 42
    assert len(report["trials"]) == 12

    assert report["sample_counts"]["B"]["attack_trials"] == 3
    assert report["sample_counts"]["B"]["benign_trials"] == 3
    assert report["sample_counts"]["B"]["latency_samples"] == 6

    assert report["sample_counts"]["C"]["latency_samples"] == 6

    assert len({t["run_id"] for t in report["trials"]}) == 12
    assert len({t["trace_id"] for t in report["trials"]}) == 12

    for trial in report["trials"]:
        assert trial["policy_version"] == "fixture-v1"
        assert trial["source"] == "fixture"
        assert trial["scenario_id"]
        assert trial["expected_result"]
        assert trial["actual_result"]

    with csv_path.open(newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))

    assert len(rows) == 2

    by_mode = {row["mode"]: row for row in rows}

    assert float(by_mode["B"]["asr"]) == 1.0
    assert float(by_mode["C"]["asr"]) == 0.0
    assert int(by_mode["B"]["total_runs"]) == 6
    assert int(by_mode["C"]["total_runs"]) == 6
