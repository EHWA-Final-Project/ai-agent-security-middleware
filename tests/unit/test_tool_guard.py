from enums import Decision, GuardExecutionStatus, InspectionMode, Stage
from fixtures import mock_runtime_observation
from schemas import SecurityContext

from security.plugins.guards.tool_guard import ToolGuard


def _context() -> SecurityContext:
    return SecurityContext(
        run_id="run-1",
        trace_id="trace-1",
        current_stage=Stage.TOOL,
        inspection_mode=InspectionMode.STANDARD,
        policy_version="v0.1.0-p0-baseline",
    )


def test_tool_guard_allows_non_sensitive_tool():
    guard = ToolGuard()
    observation = mock_runtime_observation(tool_candidate={"tool_name": "read_file", "args": {}})

    result = guard.inspect(observation, _context())

    assert result.execution_status == GuardExecutionStatus.SUCCESS
    assert result.decision == Decision.ALLOW
    assert result.risk_score == 0.0


def test_tool_guard_flags_sensitive_tool():
    guard = ToolGuard()
    observation = mock_runtime_observation(
        tool_candidate={"tool_name": "send_email", "args": {"to": "external@example.com"}}
    )

    result = guard.inspect(observation, _context())

    assert result.decision == Decision.WARN
    assert result.risk_score == 0.6
    assert result.rule_ids == ["tool_guard.sensitive_tool_invocation"]
    assert result.evidence[0]["attack_subtype"] == "TOOL_MISUSE"
    assert result.evidence[0]["tool_name"] == "send_email"


def test_tool_guard_allows_when_no_tool_candidate():
    """Defensive case — Orchestrator should never dispatch Tool Guard
    without a tool_candidate, but the guard itself should not crash if it
    somehow is.
    """
    guard = ToolGuard()
    observation = mock_runtime_observation(tool_candidate=None)

    result = guard.inspect(observation, _context())

    assert result.decision == Decision.ALLOW


def test_tool_guard_result_has_matching_run_and_trace_id():
    guard = ToolGuard()
    observation = mock_runtime_observation(tool_candidate={"tool_name": "delete_file"})

    result = guard.inspect(observation, _context())

    assert result.run_id == observation.run_id
    assert result.trace_id == observation.trace_id
    assert result.stage == Stage.TOOL
    assert result.guard_name == "tool_guard"
