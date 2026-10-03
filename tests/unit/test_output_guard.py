from enums import Decision, ExecutionState, GuardExecutionStatus, InspectionMode, Stage
from fixtures import mock_runtime_observation
from schemas import ExecutionResult, SecurityContext

from security.plugins.guards.output_guard import OutputGuard


def _context(execution_result=None) -> SecurityContext:
    return SecurityContext(
        run_id="run-1",
        trace_id="trace-1",
        current_stage=Stage.OUTPUT,
        inspection_mode=InspectionMode.STANDARD,
        policy_version="v0.1.0-p0-baseline",
        execution_result=execution_result,
    )


def test_output_guard_allows_when_no_execution_result():
    """No-tool turn: execution_result is None, nothing to inspect."""
    guard = OutputGuard()
    result = guard.inspect(mock_runtime_observation(), _context(execution_result=None))

    assert result.execution_status == GuardExecutionStatus.SUCCESS
    assert result.decision == Decision.ALLOW
    assert result.risk_score == 0.0


def test_output_guard_allows_clean_tool_output():
    execution_result = ExecutionResult(
        run_id="run-1", trace_id="trace-1", tool_name="read_file",
        execution_state=ExecutionState.EXECUTED, executed=True,
        output="Here is a summary of the document.", latency_ms=5.0,
    )
    guard = OutputGuard()
    result = guard.inspect(mock_runtime_observation(), _context(execution_result=execution_result))

    assert result.decision == Decision.ALLOW
    assert result.risk_score == 0.0


def test_output_guard_flags_leaked_api_key_in_tool_output():
    execution_result = ExecutionResult(
        run_id="run-1", trace_id="trace-1", tool_name="read_file",
        execution_state=ExecutionState.EXECUTED, executed=True,
        output="config dump: API_KEY=sk-abc123 DB_PASSWORD=hunter2", latency_ms=5.0,
    )
    guard = OutputGuard()
    result = guard.inspect(mock_runtime_observation(), _context(execution_result=execution_result))

    assert result.decision == Decision.WARN
    assert result.risk_score > 0.8
    assert result.evidence[0]["attack_subtype"] == "DATA_LEAKAGE"
    assert result.evidence[0]["matched_by_source"].get("tool_output")


def test_output_guard_distinguishes_nothing_to_check_from_checked_and_clean():
    """evidence=[] means nothing existed to check at all (no tool output,
    no context_items). evidence=[{"checked_sources": [...]}] means a
    source was present and actually checked, came back clean — a
    different, distinguishable state from "never checked".
    """
    guard = OutputGuard()

    # Nothing to check at all.
    nothing_result = guard.inspect(mock_runtime_observation(), _context(execution_result=None))
    assert nothing_result.evidence == []

    # Something present, checked, came back clean.
    execution_result = ExecutionResult(
        run_id="run-1", trace_id="trace-1", tool_name="read_file",
        execution_state=ExecutionState.EXECUTED, executed=True,
        output={"content": "Here is a clean summary."}, latency_ms=5.0,
    )
    checked_result = guard.inspect(mock_runtime_observation(), _context(execution_result=execution_result))
    assert checked_result.evidence == [{"checked_sources": ["tool_output"]}]


def test_output_guard_allows_when_tool_was_blocked():
    """Tool was blocked (executed=False, output=None) — nothing to check."""
    execution_result = ExecutionResult(
        run_id="run-1", trace_id="trace-1", tool_name="send_email",
        execution_state=ExecutionState.BLOCKED, executed=False,
        output=None, latency_ms=1.0,
    )
    guard = OutputGuard()
    result = guard.inspect(mock_runtime_observation(), _context(execution_result=execution_result))

    assert result.decision == Decision.ALLOW


def test_output_guard_checks_context_items_on_no_tool_turn():
    """No-tool turn (execution_result=None) still gets checked, against
    observation.context_items — per the team diagram, Output Guard runs
    even when the "No Tool" branch bypasses Tool Decision.
    """
    guard = OutputGuard()
    observation = mock_runtime_observation()
    observation.context_items = ["user note: API_KEY=sk-leaked-from-context"]

    result = guard.inspect(observation, _context(execution_result=None))

    assert result.decision == Decision.WARN
    assert result.evidence[0]["matched_by_source"].get("context_items")


def test_output_guard_allows_no_tool_turn_with_clean_context():
    guard = OutputGuard()
    observation = mock_runtime_observation()
    observation.context_items = ["just a normal note about the weather"]

    result = guard.inspect(observation, _context(execution_result=None))

    assert result.decision == Decision.ALLOW


def test_output_guard_sanitize_redacts_and_allows_clean_result():
    execution_result = ExecutionResult(
        run_id="run-1", trace_id="trace-1", tool_name="read_file",
        execution_state=ExecutionState.EXECUTED, executed=True,
        output="config dump: API_KEY=sk-abc123", latency_ms=5.0,
    )
    guard = OutputGuard()
    result = guard.sanitize(mock_runtime_observation(), _context(execution_result=execution_result))

    # Real redaction: after masking, the content is genuinely clean -> ALLOW.
    assert result.decision == Decision.ALLOW
    assert result.evidence == [{"sanitized": True, "sanitized_output": "config dump: [REDACTED]"}]


def test_output_guard_sanitize_also_redacts_context_items():
    """Regression guard: sanitize() must check the same sources as
    inspect(), or it can silently miss what inspect() flagged.
    context_items redaction never surfaces as sanitized_output — Runtime
    never forwards raw context_items, so there's nothing to substitute.
    """
    guard = OutputGuard()
    observation = mock_runtime_observation()
    observation.context_items = ["user note: API_KEY=sk-leaked-from-context"]

    result = guard.sanitize(observation, _context(execution_result=None))

    assert result.decision == Decision.ALLOW
    assert result.evidence == [{"sanitized": True, "sanitized_output": None}]


def test_output_guard_checks_read_file_content_key_not_text():
    """Regression test for a real bug found by 지원: read_file's actual
    output shape is {"path": ..., "content": ...} — checking a "text" key
    silently misses everything, since read_file never has one.
    """
    execution_result = ExecutionResult(
        run_id="run-1", trace_id="trace-1", tool_name="read_file",
        execution_state=ExecutionState.EXECUTED, executed=True,
        output={"path": "notes.txt", "content": "leaked: API_KEY=sk-real-bug-repro"},
        latency_ms=5.0,
    )
    guard = OutputGuard()
    result = guard.inspect(mock_runtime_observation(), _context(execution_result=execution_result))

    assert result.decision == Decision.WARN
    assert result.evidence[0]["matched_by_source"].get("tool_output")


def test_output_guard_treats_send_email_output_as_nothing_to_check():
    """send_email's output is pure metadata ({"message_id", "accepted",
    "delivery"}) — no free text to scan. Must not be checked as if it
    were a text field, and must not crash.
    """
    execution_result = ExecutionResult(
        run_id="run-1", trace_id="trace-1", tool_name="send_email",
        execution_state=ExecutionState.EXECUTED, executed=True,
        output={"message_id": "mock-message-0001", "accepted": True, "delivery": "mock"},
        latency_ms=5.0,
    )
    guard = OutputGuard()
    result = guard.inspect(mock_runtime_observation(), _context(execution_result=execution_result))

    assert result.decision == Decision.ALLOW
    assert result.evidence == []


def test_output_guard_handles_dict_shaped_execution_result_output():
    """ExecutionResult.output for read_file is {"content": ..., ...} — only
    the mapped "content" key is checked/redacted, not the whole dict.
    """
    execution_result = ExecutionResult(
        run_id="run-1", trace_id="trace-1", tool_name="read_file",
        execution_state=ExecutionState.EXECUTED, executed=True,
        output={"content": "config dump: API_KEY=sk-abc123", "metadata": {"source": "config.txt"}},
        latency_ms=5.0,
    )
    guard = OutputGuard()

    inspect_result = guard.inspect(mock_runtime_observation(), _context(execution_result=execution_result))
    assert inspect_result.decision == Decision.WARN
    assert inspect_result.evidence[0]["matched_by_source"].get("tool_output")

    sanitize_result = guard.sanitize(mock_runtime_observation(), _context(execution_result=execution_result))
    assert sanitize_result.decision == Decision.ALLOW
    assert sanitize_result.evidence[0]["sanitized_output"] == "config dump: [REDACTED]"
