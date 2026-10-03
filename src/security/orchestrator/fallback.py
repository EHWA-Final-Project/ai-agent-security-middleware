"""Guard Failure Isolation · P0 rules.
"""

from __future__ import annotations

from enums import Decision, GuardExecutionStatus, InspectionMode, Stage
from schemas import SecurityDecision, SecurityResult

_STAGES_REQUIRING_FAIL_CLOSED_BLOCK = {Stage.TOOL, Stage.OUTPUT}


def is_guard_failure(result: SecurityResult) -> bool:
    return result.execution_status in (GuardExecutionStatus.ERROR, GuardExecutionStatus.TIMEOUT)


def next_inspection_mode_on_failure(current_mode: InspectionMode) -> InspectionMode:
    """INPUT/CONTEXT failure: escalate inspection mode for the next guard."""
    return InspectionMode.STRICT


def fail_closed_decision(result: SecurityResult, *, policy_version: str) -> SecurityDecision:
    """TOOL/OUTPUT failure: produce the final fail-closed BLOCK decision."""
    return SecurityDecision(
        run_id=result.run_id,
        trace_id=result.trace_id,
        decision=Decision.BLOCK,
        reason=(
            f"Fail-closed fallback: guard '{result.guard_name}' at stage "
            f"{result.stage.value} returned execution_status="
            f"{result.execution_status.value}"
        ),
        triggered_rules=["guard_fallback_fail_closed"],
        cumulative_risk_score=1.0,
        policy_version=policy_version,
    )


def apply_guard_fallback(
    result: SecurityResult,
    *,
    current_mode: InspectionMode,
    policy_version: str,
) -> tuple[InspectionMode, SecurityDecision | None]:
    """Apply the correct fallback given a failed guard's SecurityResult.

    Returns (next_inspection_mode, final_decision_or_None).
    A non-None final_decision means the run should stop here with that
    Decision; None means proceed to the next guard under the returned mode.
    """
    if not is_guard_failure(result):
        return current_mode, None

    if result.stage in _STAGES_REQUIRING_FAIL_CLOSED_BLOCK:
        return current_mode, fail_closed_decision(result, policy_version=policy_version)

    # INPUT / CONTEXT: escalate mode only, do not block yet.
    return next_inspection_mode_on_failure(current_mode), None
