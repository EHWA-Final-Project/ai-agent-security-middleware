"""HTML presentation must escape records and preserve unknown and boundary facts."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "demo"))
import research_ui as ui


def test_html_records_escape_markup_and_preserve_unknown(monkeypatch):
    rendered = []
    monkeypatch.setattr(ui.st, "html", rendered.append)
    ui.readable_table([{"tool_name": '<img src=x onerror="alert(1)">', "unknown": None, "zero": 0}])
    html = rendered[0]
    assert "<img" not in html
    assert "&lt;img" in html
    assert "알 수 없음 / N/A" in html
    assert ">0</td>" in html


@pytest.mark.parametrize("executed,state,allowed,expected", [
    (False, "BLOCKED", False, "실행 전 차단"),
    (True, "EXECUTED", False, "실행 후 출력 통제"),
    (None, None, None, "실행 경계 미확인"),
])
def test_runtime_boundary_uses_execution_facts(monkeypatch, executed, state, allowed, expected):
    rendered = []
    monkeypatch.setattr(ui.st, "html", rendered.append)
    monkeypatch.setattr(ui.st, "info", lambda *_: None)
    ui.execution_summary({"tool_executed": executed, "execution_state": state,
                          "output_allowed": allowed, "security_decision": "BLOCK"}, runtime=True)
    assert expected in rendered[0]
