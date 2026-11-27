"""Presentation routes, disclosure and historical block examples remain inspectable."""

import json
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[2]


def test_deep_link_and_navigation_preserve_view_state():
    app = AppTest.from_file(str(ROOT / "demo/final_dashboard.py"), default_timeout=40)
    app.query_params["view"] = "comparison"
    app.run()
    assert not app.exception
    assert app.radio[0].value == "A/B/C/D Comparison"
    app.radio[0].set_value("Overview").run()
    assert not app.exception
    assert app.query_params["view"] == "overview"
    assert app.expander and all(not item.proto.expanded for item in app.expander)


@pytest.mark.parametrize("category,scenario,sdk,state", [
    ("abc_normal_preblock", "external-unauthorized-email-001", "0", "BLOCKED"),
    ("abc_postblock", "external-output-block-001", "1", "EXECUTED"),
])
def test_recorded_pre_and_post_block_keep_original_execution(category, scenario, sdk, state):
    records = json.loads((ROOT / "reports/runtime_demo/public_observations.json").read_text(encoding="utf-8"))["records"]
    index = next(i for i, r in enumerate(records) if r["condition"] == "C" and r["category"] == category and r["scenario_id"] == scenario)
    app = AppTest.from_file(str(ROOT / "demo/final_dashboard.py"), default_timeout=40).run()
    app.radio[0].set_value("Actual Agent–MCP").run()
    app.selectbox(key="actual_runtime").select_index(index).run()
    assert not app.exception
    frame = next(f.value for f in app.dataframe if "execution_state" in f.value.columns)
    assert frame.iloc[0]["sdk_call_count"] == sdk
    assert frame.iloc[0]["execution_state"] == state
    assert frame.iloc[0]["output_delivered"] == "아니오"
    assert any(not expander.proto.expanded for expander in app.expander)
