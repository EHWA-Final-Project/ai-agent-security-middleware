"""Synthetic integration fixtures; never public benchmark evidence."""

import json

import pytest

from evaluation import benchmark_report as report
from evaluation.benchmark_adapter import BenchmarkSample, text_sha256


@pytest.fixture
def scenarios():
    result = []
    for dataset in ("bipia", "notinject"):
        text = "Synthetic unit fixture."
        result.append(BenchmarkSample(
            sample_id=f"synthetic:{dataset}", dataset_id=dataset, revision="a" * 40,
            source_url=f"https://example.test/{'a' * 40}/sample.json",
            source_file="sample.json", source_sha256="b" * 64,
            source_locator="/0", split="synthetic", text=text,
            text_sha256=text_sha256(text), attack_family="synthetic" if dataset == "bipia" else None,
        ).to_scenario())
    return result


def test_paired_sweep_exports_valid_denominators(tmp_path, scenarios, monkeypatch):
    monkeypatch.setattr(report, "render_benchmark_graphs", lambda *args: None)
    output = tmp_path / "run"
    result = report.run_benchmark_sweep(output, scenarios=scenarios, manifest={},
                                       thresholds=(.7, .8, .9, .92, .98), repeats=2)
    assert result["experiment"]["total_trials"] == 40
    assert report.read_benchmark_summary(output / "summary.json") == result
    rows = [json.loads(line) for line in (output / "trials.jsonl").read_text().splitlines()]
    assert len({row["run_id"] for row in rows}) == 40
    assert len({row["pair_id"] for row in rows}) == 20
    for cell in result["cells"]:
        assert cell["metrics"]["asr"] is None
        assert cell["metrics"]["tsr"] is None
        assert cell["sample_counts"]["asr_denominator"] == 0
        assert cell["sample_counts"]["fpr_denominator"] == 2
        assert cell["sample_counts"]["unique_samples"] == 2
    with pytest.raises(FileExistsError):
        report.run_benchmark_sweep(output, scenarios=scenarios, manifest={})


def test_graph_failure_cannot_publish_success(tmp_path, scenarios, monkeypatch):
    def fail(*args):
        raise RuntimeError("synthetic graph failure")
    monkeypatch.setattr(report, "render_benchmark_graphs", fail)
    output = tmp_path / "failed"
    with pytest.raises(RuntimeError, match="synthetic"):
        report.run_benchmark_sweep(output, scenarios=scenarios, manifest={}, thresholds=(.8,))
    assert not (output / "summary.json").exists()
    assert json.loads((output / "failure.json").read_text())["status"] == "failed"


def test_invalid_thresholds_do_not_create_report(tmp_path, scenarios):
    with pytest.raises(ValueError, match="thresholds"):
        report.run_benchmark_sweep(tmp_path / "bad", scenarios=scenarios, manifest={}, thresholds=(.8, .8))
    assert not (tmp_path / "bad").exists()
