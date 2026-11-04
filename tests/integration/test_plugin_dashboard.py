"""Presentation replay must not invoke Runtime again or alter saved Evidence."""

import importlib
import json
import sqlite3
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
    assert [tab.label for tab in at.tabs] == [
        "Plugin Execution Trace", "A/B/C Evaluation", "Attack Playground", "Benchmark Lab",
    ]
    assert any("Guard 실행 흐름" in sub.value for sub in at.subheader)
    assert not at.sidebar.selectbox
    assert not at.sidebar.button
    assert at.expander[0].label == "이전 실행 불러오기"
    assert at.expander[0].proto.expanded is False
    assert [at.button(key=f"scenario_{key}").label for key in ("1", "2", "3")] == ["실행"] * 3
    assert any("예상 결과" in item.value for item in at.caption)
    snapshots = []
    for key, expected in (("1", ("ALLOW", 1, True)), ("2", ("BLOCK", 0, False)), ("3", ("BLOCK", 1, False))):
        at.button(key=f"scenario_{key}").click().run()
        assert not at.exception, at.exception
        snapshot = service.list_runs()[0]
        snapshots.append(snapshot)
        result = snapshot["result"]
        assert (result["decision"]["decision"], snapshot["tool_calls"], result["output_allowed"]) == expected
        assert result["errors"] == []
        assert [(metric.label, metric.value) for metric in at.metric[:4]] == [
            ("최종 판정", expected[0]),
            ("Tool 실행 여부", "실행됨" if expected[1] else "미실행"),
            ("Output 전달 여부", "전달" if expected[2] else "차단"),
            ("Evidence 저장 여부", "저장 확인"),
        ]
        assert at.session_state["selected_run"] == result["identity"]["run_id"]
        events = service.query_events(result["identity"]["run_id"])
        assert events
        assert all(e["run_id"] == result["identity"]["run_id"] and e["trace_id"] == result["identity"]["trace_id"] for e in events)
        assert all(item.proto.expanded is False for item in at.expander)

    run_id = snapshots[-1]["result"]["identity"]["run_id"]
    before = deepcopy(service.query_events(run_id))
    view = importlib.import_module("plugin_view")
    assert view.replay_caption(before, len(before) - 1) in [item.value for item in at.info]
    assert [at.button(key=key).label for key in ("replay_start", "replay_next", "replay_reset", "replay_all")] == [
        "▶ 자동으로 흐름 보기", "→ 한 단계씩 보기", "↺ 처음부터", "✓ 최종 결과 보기",
    ]
    at.button(key="replay_reset").click().run()
    assert at.session_state["replay_cursor"] == -1
    at.button(key="replay_next").click().run()
    assert at.session_state["replay_cursor"] == 0
    assert before[0]["event_type"] == "RUN_STATUS"
    assert before[0]["payload"]["run_status"] == "CREATED"
    assert view.replay_caption(before, 0) in [item.value for item in at.info]
    assert not any("저장 Evidence 1/" in item.value and "COMPLETED" in item.value for item in at.info)
    at.button(key="replay_start").click().run()
    assert at.session_state["replay_cursor"] == -1
    assert at.session_state["replay_playing"] is True
    at.run()
    assert at.session_state["replay_cursor"] == 0
    assert view.replay_caption(before, 0) in [item.value for item in at.info]
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
    with sqlite3.connect(service.DB.as_uri() + "?mode=ro", uri=True) as connection:
        raw = connection.execute(
            "SELECT event_id, created_at, event_type, payload FROM security_events WHERE run_id = ? ORDER BY created_at ASC",
            (snapshot["result"]["identity"]["run_id"],),
        ).fetchall()
    assert [row[0] for row in raw] == [row["event_id"] for row in rows]
    assert [row[1] for row in raw] == [event["created_at"].replace("Z", "+00:00") for event in events]
    assert raw[0][2] == "RUN_STATUS" and json.loads(raw[0][3])["run_status"] == "CREATED"
    assert raw[-1][2] == "RUN_STATUS" and json.loads(raw[-1][3])["run_status"] == "COMPLETED"
    # Even unusual repository order must not be silently "corrected" in the UI.
    reversed_events = list(reversed(events))
    assert [row["event_id"] for row in view.replay_rows(reversed_events, 0)] == [event["event_id"] for event in reversed_events]
    assert "COMPLETED" in view.replay_caption(reversed_events, 0)


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
    assert sum("Condition" in item.value.columns for item in at.dataframe) == 2
    assert any("B vs C" in text.value for text in at.markdown)
    assert any("summary에 없어" in text.value for text in at.caption)
    configuration = [item.value for item in at.markdown]
    assert "**Guard Plugins: ALL OFF**" in configuration
    assert configuration.count("**Guard Plugins: 4 ON**") == 2
    assert [item for item in configuration if item.startswith("**Cross-layer Coordination:")] == [
        "**Cross-layer Coordination: N/A**", "**Cross-layer Coordination: OFF**", "**Cross-layer Coordination: ON**",
    ]
    settings = next(item for item in at.expander if item.label == "발표 설정 / Report 경로")
    assert settings.proto.expanded is False
    assert len(settings.text_input) == 1
    assert not any("Evaluation 결과 파일이 없습니다" in item.value for item in at.info)
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
    assert next(item.value for item in at.metric if item.label == "Evidence 저장 여부") == "기록 없음"


def test_guard_error_and_timeout_take_priority_over_allow(dashboard):
    at = AppTest.from_string(
        "from plugin_view import show_status\nshow_status('ALLOW', 'ERROR')\nshow_status('WARN', 'TIMEOUT')",
    ).run()
    assert not at.exception
    assert len(at.error) == 2
    assert not at.success


def test_pipeline_highlights_only_recorded_stages_and_preserves_rechecks(dashboard):
    service, _, _ = dashboard
    view = importlib.import_module("plugin_view")
    snapshot = service.run_scenario("2")
    events = service.query_events(snapshot["result"]["identity"]["run_id"])
    original = deepcopy(events)
    guard_index = next(i for i, event in enumerate(events) if event["event_type"] == "SECURITY_RESULT")
    stage = events[guard_index]["payload"]["stage"]
    assert view.pipeline_step(events, -1, {"SECURITY_RESULT"}, stage)["phase"] == "pending"
    current = view.pipeline_step(events, guard_index, {"SECURITY_RESULT"}, stage)
    assert current["phase"] == "current"
    assert current["events"][-1] == events[guard_index]
    assert view.pipeline_step(events, len(events) - 1, {"SECURITY_RESULT"}, stage)["phase"] == "complete"
    assert view.pipeline_step(events, len(events) - 1, {"SECURITY_RESULT"}, "OUTPUT") == {"phase": "missing", "events": []}
    assert view.pipeline_step(events, 0, {"PLUGIN_MANAGER_DISPATCH"})["phase"] == "missing"
    repeated = [events[guard_index], deepcopy(events[guard_index])]
    assert view.pipeline_step(repeated, 0, {"SECURITY_RESULT"}, stage)["phase"] == "current"
    assert view.pipeline_step(repeated, 1, {"SECURITY_RESULT"}, stage)["events"] == repeated
    assert events == original


def test_evidence_summary_requires_matching_payload_identity(dashboard):
    service, _, _ = dashboard
    view = importlib.import_module("plugin_view")
    snapshot = service.run_scenario("1")
    events = service.query_events(snapshot["result"]["identity"]["run_id"])
    assert view.evidence_status(events, snapshot) == "저장 확인"
    events[0]["payload"]["trace_id"] = "different-trace"
    assert view.evidence_status(events, snapshot) == "확인 필요"


def test_benchmark_pending_and_attack_catalog_do_not_execute_runtime(dashboard):
    _, _, calls = dashboard
    at = AppTest.from_file(str(ROOT / "demo" / "dashboard.py"), default_timeout=30).run()
    assert not at.exception
    assert calls == []
    assert any(item.value == "결과 없음" for item in at.info)
    assert not at.tabs[3].metric
    catalog = next(item.value for item in at.dataframe if "Attack ID" in item.value.columns)
    assert len(catalog) == 9
    assert "Encoded / Obfuscated Instruction" in catalog["공격 유형"].tolist()
    assert sum("준비 중" in status for status in catalog["실행 / 검증 상태"]) == 7
    assert [button.key for button in at.button if (button.key or "").startswith("scenario_")] == [
        "scenario_1", "scenario_2", "scenario_3",
    ]


def test_warn_summary_uses_recorded_execution_and_output(dashboard, monkeypatch):
    service, _, _ = dashboard
    snapshot = service.run_scenario("1")
    snapshot["result"]["decision"]["decision"] = "WARN"
    snapshot["result"]["output_allowed"] = False
    monkeypatch.setattr(service, "list_runs", lambda: [snapshot])
    at = AppTest.from_file(str(ROOT / "demo" / "dashboard.py"), default_timeout=30).run()
    assert not at.exception
    assert [metric.value for metric in at.metric[:3]] == ["WARN", "실행됨", "차단"]
    assert any("WARN은 경고 판정" in item.value for item in at.warning)
    assert not any("실행 전 차단: 실제 Tool" in item.value for item in at.info)


def test_benchmark_invalid_handoff_is_visible_without_running_tools(dashboard, tmp_path):
    _, _, calls = dashboard
    (tmp_path / 'holdout_results.json').write_text('{', encoding='utf-8')
    at = AppTest.from_file(str(ROOT / 'demo' / 'dashboard.py'), default_timeout=30).run()
    at.text_input(key='holdout_directory').set_value(str(tmp_path)).run()
    assert not at.exception
    assert at.warning
    assert not at.tabs[3].metric
    assert calls == []


def test_benchmark_summary_only_displays_unknown_numerators(dashboard, tmp_path):
    _, _, calls = dashboard
    from benchmark_reader import METRICS, THRESHOLDS

    rows = [dict(condition=mode, threshold=threshold, n_attack=4,
                 n_benign_read=2, n_benign_send=2, **dict.fromkeys(METRICS, 0.5))
            for mode, thresholds in (('A', [None]), ('B', THRESHOLDS), ('C', THRESHOLDS))
            for threshold in thresholds]
    data = {'kind': 'benchmark_evaluation', 'split': 'holdout', 'run': {}, 'data': {},
            'headline_block_threshold': 0.8, 'tool_policy': {}, 'notes': [],
            'sweep_default': rows, 'sweep_with_tool_policy': rows, 'c_block_cause': []}
    (tmp_path / 'holdout_results.json').write_text(json.dumps(data), encoding='utf-8')
    at = AppTest.from_file(str(ROOT / 'demo' / 'dashboard.py'), default_timeout=30).run()
    at.text_input(key='holdout_directory').set_value(str(tmp_path)).run()
    assert not at.exception
    table = next(frame.value for frame in at.dataframe if 'numerator' in frame.value.columns)
    assert table['numerator'].isna().all()
    assert set(table['policy']) == {'default', 'tool_policy'}
    assert calls == []


def test_live_bc_comparison_has_isolated_evidence_and_survives_rerun(dashboard):
    service, _, calls = dashboard
    at = AppTest.from_file(str(ROOT / 'demo' / 'dashboard.py'), default_timeout=30).run()
    at.button(key='run_bc_comparison').click().run()
    assert not at.exception
    snapshots = at.session_state['bc_comparison']
    identities = [s['result']['identity'] for s in snapshots.values()]
    assert len({i['run_id'] for i in identities}) == 2
    assert len({i['trace_id'] for i in identities}) == 2
    for mode, snapshot in snapshots.items():
        result = snapshot['result']
        assert snapshot['tool_calls'] == 1 and result['output_allowed'] is True
        assert f'-cond-{mode.lower()}-' in result['decision']['policy_version']
        events = service.query_events(result['identity']['run_id'])
        assert events and all(e['trace_id'] == result['identity']['trace_id'] for e in events)
    assert len(service.list_runs()) == 2
    at.run()
    assert not at.exception
    assert len(service.list_runs()) == 2
    assert calls == []


@pytest.mark.parametrize('key,expected', [('1', ('ALLOW', 1, True)), ('2', ('BLOCK', 0, False)), ('3', ('BLOCK', 1, False))])
def test_bc_boundary_matrix_has_linked_result_decision_execution(dashboard, key, expected):
    service, _, _ = dashboard
    snapshots = service.run_comparison(key)
    assert snapshots['B']['scenario'] == snapshots['C']['scenario']
    for snapshot in snapshots.values():
        result = snapshot['result']
        assert (result['decision']['decision'], snapshot['tool_calls'], result['output_allowed']) == expected
        events = service.query_events(result['identity']['run_id'])
        assert {'SECURITY_RESULT', 'SECURITY_DECISION', 'EXECUTION_RESULT', 'RUN_STATUS'} <= {e['event_type'] for e in events}
        assert all(e['payload']['run_id'] == result['identity']['run_id'] and e['payload']['trace_id'] == result['identity']['trace_id'] for e in events)
        assert len({e['event_id'] for e in events}) == len(events)
        assert [e['created_at'] for e in events] == sorted(e['created_at'] for e in events)


def test_incomplete_evidence_is_not_confirmed_and_duplicate_replay_is_preserved(dashboard):
    service, _, _ = dashboard
    view = importlib.import_module('plugin_view')
    snapshot = service.run_scenario('1')
    events = service.query_events(snapshot['result']['identity']['run_id'])
    incomplete = [e for e in events if e['event_type'] != 'EXECUTION_RESULT']
    assert view.evidence_status(incomplete, snapshot) != view.evidence_status(events, snapshot)
    duplicate = [events[0], deepcopy(events[0])]
    assert len(view.replay_rows(duplicate, 0)) == 2
    del duplicate[1]['event_id']
    assert len(view.replay_rows(duplicate, 0)) == 2


def test_reviewed_dashboard_shows_eight_graphs_without_runtime_rerun(dashboard, tmp_path, monkeypatch):
    from demo.reviewed_package import import_archive
    from tests.unit.test_reviewed_package import archive, synthetic_package

    _, _, calls = dashboard
    files, _ = synthetic_package()
    root = tmp_path / 'package'
    import_archive(archive(tmp_path, files), root)
    monkeypatch.setenv('GUARDON_EVALUATION_HANDOFF', str(root))
    at = AppTest.from_file(str(ROOT / 'demo/dashboard.py'), default_timeout=60).run()
    assert not at.exception, at.exception
    assert len(at.get('image')) == 8
    assert any('review_package_integrity_checked' in item.value for item in at.json)
    at.run()
    assert not at.exception
    assert len(at.get('image')) == 8
    assert calls == []


def test_reviewed_dashboard_hides_changed_package_graphs(dashboard, tmp_path, monkeypatch):
    from demo.reviewed_package import import_archive
    from tests.unit.test_reviewed_package import archive, synthetic_package

    _, _, calls = dashboard
    files, _ = synthetic_package()
    root = tmp_path / 'package'
    import_archive(archive(tmp_path, files), root)
    (root / 'tuning/figures/core_latency.png').write_bytes(b'changed')
    monkeypatch.setenv('GUARDON_EVALUATION_HANDOFF', str(root))
    at = AppTest.from_file(str(ROOT / 'demo/dashboard.py'), default_timeout=60).run()
    assert not at.exception, at.exception
    assert not at.get('image')
    assert at.warning
    assert calls == []
