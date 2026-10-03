from enums import Decision, GuardExecutionStatus, InspectionMode, Stage
from schemas import SecurityResult

from security.orchestrator.fallback import apply_guard_fallback


def _failed_result(stage: Stage, status: GuardExecutionStatus) -> SecurityResult:
    return SecurityResult(
        run_id="run-1",
        trace_id="trace-1",
        stage=stage,
        guard_name=f"{stage.value.lower()}_guard",
        execution_status=status,
        risk_score=None,
        decision=None,
        latency_ms=5000.0,
    )


def test_input_stage_failure_escalates_mode_but_does_not_block():
    result = _failed_result(Stage.INPUT, GuardExecutionStatus.TIMEOUT)

    next_mode, decision = apply_guard_fallback(
        result, current_mode=InspectionMode.STANDARD, policy_version="v0.1.0-p0-baseline"
    )

    assert next_mode == InspectionMode.STRICT
    assert decision is None


def test_context_stage_failure_escalates_mode_but_does_not_block():
    result = _failed_result(Stage.CONTEXT, GuardExecutionStatus.ERROR)

    next_mode, decision = apply_guard_fallback(
        result, current_mode=InspectionMode.STANDARD, policy_version="v0.1.0-p0-baseline"
    )

    assert next_mode == InspectionMode.STRICT
    assert decision is None


def test_tool_stage_failure_produces_fail_closed_block():
    result = _failed_result(Stage.TOOL, GuardExecutionStatus.TIMEOUT)

    _next_mode, decision = apply_guard_fallback(
        result, current_mode=InspectionMode.STANDARD, policy_version="v0.1.0-p0-baseline"
    )

    assert decision is not None
    assert decision.decision == Decision.BLOCK
    assert decision.run_id == "run-1"
    assert decision.trace_id == "trace-1"


def test_output_stage_failure_produces_fail_closed_block():
    result = _failed_result(Stage.OUTPUT, GuardExecutionStatus.ERROR)

    _, decision = apply_guard_fallback(
        result, current_mode=InspectionMode.STANDARD, policy_version="v0.1.0-p0-baseline"
    )

    assert decision is not None
    assert decision.decision == Decision.BLOCK


def test_successful_guard_is_not_treated_as_failure():
    result = SecurityResult(
        run_id="run-1",
        trace_id="trace-1",
        stage=Stage.TOOL,
        guard_name="tool_guard",
        execution_status=GuardExecutionStatus.SUCCESS,
        risk_score=0.1,
        decision=Decision.ALLOW,
        latency_ms=10.0,
    )

    next_mode, decision = apply_guard_fallback(
        result, current_mode=InspectionMode.STANDARD, policy_version="v0.1.0-p0-baseline"
    )

    assert decision is None
    assert next_mode == InspectionMode.STANDARD
