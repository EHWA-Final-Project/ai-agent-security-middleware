"""Exercise the actual Streamlit app, all views and read-only candidate replay."""

import hashlib
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[2]


def test_all_final_views_and_replay_do_not_execute_tools(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "demo"))
    import service

    def forbidden(*args, **kwargs):
        raise AssertionError("Replay must not invoke Runtime")

    monkeypatch.setattr(service, "run_scenario", forbidden)
    monkeypatch.setattr(service, "list_runs", list)
    source = ROOT / "reports/external_mcp_actual/dashboard/candidate_observations.json"
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    app = AppTest.from_file(str(ROOT / "demo/final_dashboard.py"), default_timeout=40).run()
    assert not app.exception, app.exception
    assert not app.error
    assert any("저장된 실제 실험 결과" in item.value for item in app.info)
    for view in ("Actual Agent–MCP", "A/B/C/D Comparison", "External Benchmark", "Evidence / Replay"):
        app.radio[0].set_value(view).run()
        assert not app.exception, app.exception
        assert not app.error
        assert app.dataframe
        if view == "External Benchmark":
            assert len(app.get("image")) == 5
        if view == "Evidence / Replay":
            app.selectbox(key="replay_trial").select_index(1).run()
            assert not app.exception
            app.select_slider[0].set_value(2).run()
            assert not app.exception
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
