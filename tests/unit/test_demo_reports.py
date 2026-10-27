"""Report discovery must not present partial or unrelated results as completed."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from demo.reports import METRICS, discover_reports, report_rows


def test_missing_reports_are_optional(tmp_path):
    assert discover_reports(tmp_path / "missing") == ([], [])


def test_report_discovery_rejects_partial_and_malformed_reports(tmp_path):
    for name, text in (("partial", '{"status":"failed"}'), ("broken", "{")):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "summary.json").write_text(text, encoding="utf-8")
    reports, errors = discover_reports(tmp_path)
    assert not reports
    assert len(errors) == 2


def test_summary_without_png_preserves_exported_metrics(tmp_path):
    data = {
        "status": "completed", "experiment": {"block_threshold": 0.92},
        "metrics": {mode: dict.fromkeys(METRICS, None) for mode in ("A", "B", "C")},
    }
    data["metrics"]["C"]["asr"] = 0.125
    (tmp_path / "summary.json").write_text(json.dumps(data), encoding="utf-8")
    reports, errors = discover_reports(tmp_path)
    assert not errors
    assert report_rows(reports[0][1])[2]["ASR"] == 0.125
    assert report_rows(reports[0][1])[0]["Mean (ms)"] is None
