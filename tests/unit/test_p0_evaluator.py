import json
from pathlib import Path

from enums import Decision, ExecutionState, RunStatus
from schemas.runtime import ExecutionResult
from schemas.security import SecurityDecision

from evaluation import P0Evaluator

FIXTURE_DIR = Path(__file__).parents[2] / "shared" / "fixtures"


def load_fixture(name: str) -> dict:
    path = FIXTURE_DIR / name
    return json.loads(path.read_text(encoding="utf-8"))


def make_decision(
    *,
    decision: Decision,
    run_id: str = "run-eval-001",
    trace_id: str = "trace-eval-001",
) -> SecurityDecision:
    return SecurityDecision(
        run_id=run_id,
        trace_id=trace_id,
        decision=decision,
        reason="P0 evaluation test",
        triggered_rules=[],
        cumulative_risk_score=0.0,
        policy_version="p0-test",
    )


def make_execution(
    *,
    executed: bool,
    execution_state: ExecutionState,
    run_id: str = "run-eval-001",
    trace_id: str = "trace-eval-001",
) -> ExecutionResult:
    return ExecutionResult(
        run_id=run_id,
        trace_id=trace_id,
        tool_call_id="tool-eval-001",
        tool_name="test_tool",
        execution_state=execution_state,
        executed=executed,
        output=None,
        error=None,
        latency_ms=1.0,
    )


def test_benign_expected_result_is_task_success():
    scenario = load_fixture("benign_001.json")
    evaluator = P0Evaluator()

    result = evaluator.evaluate(
        scenario=scenario,
        security_decision=make_decision(decision=Decision.ALLOW),
        execution_result=make_execution(
            executed=True,
            execution_state=ExecutionState.EXECUTED,
        ),
        run_status=RunStatus.COMPLETED,
    )

    assert result.task_success is True
    assert result.false_positive is False
    assert result.attack_success is None

    assert result.actual_result["final_decision"] == "ALLOW"
    assert result.actual_result["executed"] is True
    assert result.actual_result["execution_state"] == "EXECUTED"
    assert result.actual_result["run_status"] == "COMPLETED"


def test_benign_block_is_false_positive_and_task_failure():
    scenario = load_fixture("benign_001.json")
    evaluator = P0Evaluator()

    result = evaluator.evaluate(
        scenario=scenario,
        security_decision=make_decision(decision=Decision.BLOCK),
        execution_result=make_execution(
            executed=False,
            execution_state=ExecutionState.BLOCKED,
        ),
        run_status=RunStatus.COMPLETED,
    )

    assert result.task_success is False
    assert result.false_positive is True
    assert result.attack_success is None


def test_attack_blocked_means_attack_did_not_succeed():
    scenario = load_fixture("attack_001.json")
    evaluator = P0Evaluator()

    result = evaluator.evaluate(
        scenario=scenario,
        security_decision=make_decision(decision=Decision.BLOCK),
        execution_result=make_execution(
            executed=False,
            execution_state=ExecutionState.BLOCKED,
        ),
        run_status=RunStatus.COMPLETED,
    )

    assert result.attack_success is False
    assert result.task_success is None
    assert result.false_positive is None

    assert result.actual_result["final_decision"] == "BLOCK"
    assert result.actual_result["executed"] is False


def test_attack_execution_means_attack_succeeded():
    scenario = load_fixture("attack_001.json")
    evaluator = P0Evaluator()

    result = evaluator.evaluate(
        scenario=scenario,
        security_decision=make_decision(decision=Decision.ALLOW),
        execution_result=make_execution(
            executed=True,
            execution_state=ExecutionState.EXECUTED,
        ),
        run_status=RunStatus.COMPLETED,
    )

    assert result.attack_success is True
    assert result.task_success is None
    assert result.false_positive is None
    