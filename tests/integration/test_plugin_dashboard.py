"""Presentation replay must not invoke Runtime again or alter saved Evidence."""

import importlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def dashboard(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(ROOT / "demo"))
    service = importlib.import_module("service")
    reports = importlib.import_module("reports")
    monkeypatch.setattr(service, "DATA", tmp_path / "runs")
    monkeypatch.setattr(service, "DB", tmp_path / "runs" / "evidence.db")
    monkeypatch.setattr(reports, "ROOT", tmp_path)
    calls = []
    original = service.run_scenario

    def counted_run(key):
        calls.append(key)
        return original(key)

    monkeypatch.setattr(service, "run_scenario", counted_run)
    return service, reports, calls


def test_runtime_scenarios_replay_and_run_switch_preserve_evidence(dashboard):
    service, _, calls = dashboard
    at = AppTest.from_file(str(ROOT / "demo" / "dashboard.py"), default_timeout=30).run()
    assert not at.exception
    assert [tab.label for tab in at.tabs] == ["Plugin Execution Trace", "A/B/C Evaluation"]
    assert any("Plugin Architecture" in sub.value for sub in at.subheader)
    snapshots = []
    for key, expected in (("1", ("ALLOW", 1, True)), ("2", ("BLOCK", 0, False)), ("3", ("BLOCK", 1, False))):
        at.button(key=f"scenario_{key}").click().run()
        assert not at.exception, at.exception
        snapshot = service.list_runs()[0]
        snapshots.append(snapshot)
        result = snapshot["result"]
        assert (result["decision"]["decision"], snapshot["tool_calls"], result["output_allowed"]) == expected
        assert result["errors"] == []
        assert at.session_state["selected_run"] == result["identity"]["run_id"]
        events = service.query_events(result["identity"]["run_id"])
        assert events
        assert all(e["run_id"] == result["identity"]["run_id"] and e["trace_id"] == result["identity"]["trace_id"] for e in events)

    run_id = snapshots[-1]["result"]["identity"]["run_id"]
    before = deepcopy(service.query_events(run_id))
    at.button(key="replay_reset").click().run()
    assert at.session_state["replay_cursor"] == -1
    at.button(key="replay_next").click().run()
    assert at.session_state["replay_cursor"] == 0
    at.button(key="replay_start").click().run()
    assert at.session_state["replay_cursor"] == -1
    assert at.session_state["replay_playing"] is True
    at.run()
    assert at.session_state["replay_cursor"] == 0
    at.button(key="replay_next").click().run()
    assert at.session_state["replay_cursor"] == 1
    assert at.session_state["replay_playing"] is False
    at.button(key="replay_start").click().run()
    for _ in before:
        at.run()
    assert at.session_state["replay_cursor"] == len(before) - 1
    assert at.session_state["replay_playing"] is False
    at.button(key="replay_all").click().run()
    assert at.session_state["replay_cursor"] == len(before) - 1
    assert service.query_events(run_id) == before
    assert calls == ["1", "2", "3"]
    old_id = snapshots[0]["result"]["identity"]["run_id"]
    at.selectbox(key="selected_run").select(old_id).run()
    assert not at.exception
    assert at.session_state["replay_run"] == old_id
    assert at.session_state["replay_playing"] is False


def test_replay_does_not_invent_or_reorder_events(dashboard):
    service, _, _ = dashboard
    view = importlib.import_module("plugin_view")
    snapshot = service.run_scenario("2")
    events = service.query_events(snapshot["result"]["identity"]["run_id"])
    original = deepcopy(events)
    rows = view.replay_rows(events, 1)
    assert [row["event_id"] for row in rows] == [event["event_id"] for event in events]
    assert len(rows) == len(events)
    assert rows[1]["Replay"] == "▶ CURRENT"
    assert rows[0]["Replay"] == "✓ 완료"
    assert rows[2]["Replay"] == "○ pending"
    assert events == original
    assert all("Plugin Manager" not in row["Event"] for row in rows)


def test_evaluation_configuration_and_summary_only_comparison(dashboard, tmp_path):
    _, reports, _ = dashboard
    for threshold in (0.80, 0.92):
        directory = tmp_path / "reports" / str(threshold)
        directory.mkdir(parents=True)
        data = {
            "status": "completed", "experiment": {"block_threshold": threshold},
            "metrics": {mode: dict.fromkeys(reports.METRICS, None) for mode in ("A", "B", "C")},
        }
        (directory / "summary.json").write_text(json.dumps(data), encoding="utf-8")
    at = AppTest.from_file(str(ROOT / "demo" / "dashboard.py"), default_timeout=30).run()
    assert not at.exception, at.exception
    assert len(at.dataframe) == 2  # summary-only reports; no PNG or invented trial data
    assert any("B vs C" in text.value for text in at.markdown)
    assert any("summary에 없어" in text.value for text in at.caption)
    view = importlib.import_module("plugin_view")
    a, b, c = (view.condition_config(mode) for mode in ("A", "B", "C"))
    assert not any(plugin["enabled"] for plugin in a["plugins"])
    assert all(plugin["enabled"] for plugin in b["plugins"] + c["plugins"])
    assert b["plugins"] == c["plugins"]
    assert b["mode"] == "independent" and c["mode"] == "linked"


def test_missing_evidence_does_not_claim_persistence_success(dashboard, monkeypatch):
    service, _, _ = dashboard
    monkeypatch.setattr(service, "query_events", lambda run_id: [])
    at = AppTest.from_file(str(ROOT / "demo" / "dashboard.py"), default_timeout=30).run()
    at.button(key="scenario_1").click().run()
    assert not at.exception, at.exception
    assert not any("SQLite persistence OK" in item.value for item in at.success)
    assert any("저장 Evidence 없음" in item.value for item in at.caption)


def test_guard_error_and_timeout_take_priority_over_allow(dashboard):
    at = AppTest.from_string(
        "from plugin_view import show_status\nshow_status('ALLOW', 'ERROR')\nshow_status('WARN', 'TIMEOUT')",
    ).run()
    assert not at.exception
    assert len(at.error) == 2
    assert not at.success
