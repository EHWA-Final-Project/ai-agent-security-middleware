"""Output Guard behavior for MCP ``server/tool`` names."""

import pytest
from enums import Decision, ExecutionState, InspectionMode, Stage
from fixtures import mock_runtime_observation
from schemas import ExecutionResult, SecurityContext

from security.plugins.guards.output_guard import OutputGuard


def _context(tool_name, output) -> SecurityContext:
    return SecurityContext(
        run_id="run-1", trace_id="trace-1", current_stage=Stage.OUTPUT,
        inspection_mode=InspectionMode.STANDARD, policy_version="v0.1.0-p0-baseline",
        execution_result=ExecutionResult(
            run_id="run-1", trace_id="trace-1", tool_name=tool_name,
            execution_state=ExecutionState.EXECUTED, executed=True, output=output, latency_ms=5.0,
        ),
    )


@pytest.mark.parametrize("tool", ["read_file", "demo/read_file", "other/read_file"])
def test_secret_in_read_file_content_is_flagged_for_bare_and_qualified_names(tool):
    ctx = _context(tool, {"path": "a.txt", "content": "dump: API_KEY=sk-abc123"})
    r = OutputGuard().inspect(mock_runtime_observation(), ctx)
    assert r.decision == Decision.WARN
    assert r.evidence[0]["matched_by_source"].get("tool_output")


@pytest.mark.parametrize("tool", ["read_file", "demo/read_file"])
def test_sanitize_redacts_qualified_read_file_content(tool):
    ctx = _context(tool, {"path": "a.txt", "content": "dump: API_KEY=sk-abc123"})
    r = OutputGuard().sanitize(mock_runtime_observation(), ctx)
    assert r.decision == Decision.ALLOW
    assert r.evidence[0]["sanitized"] is True
    assert "sk-abc123" not in r.evidence[0]["sanitized_output"]


def test_clean_qualified_read_file_is_checked_and_allowed():
    ctx = _context("demo/read_file", {"path": "a.txt", "content": "hello"})
    r = OutputGuard().inspect(mock_runtime_observation(), ctx)
    assert r.decision == Decision.ALLOW
    assert r.evidence == [{"checked_sources": ["tool_output"]}]


def test_qualified_send_email_output_is_still_nothing_to_check():
    ctx = _context("demo/send_email", {"message_id": "m-1", "accepted": True, "delivery": "mock"})
    r = OutputGuard().inspect(mock_runtime_observation(), ctx)
    assert r.decision == Decision.ALLOW and r.evidence == []
