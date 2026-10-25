import json
from pathlib import Path

import pytest
from enums import Decision, ExecutionState, RunStatus, ScenarioType
from schemas.runtime import ExecutionResult
from schemas.security import SecurityDecision

from evaluation.experiment_runner import (
    ExperimentRunner,
    TrialOutput,
    TrialRequest,
)
from evaluation.metrics_aggregator import MetricsAggregator

FIXTURE_DIR = Path(__file__).parents[2] / "shared" / "fixtures"


def load_fixture(name: str) -> dict:
    path = FIXTURE_DIR / name
    return json.loads(path.read_text(encoding="utf-8"))


def mock_execute_trial(request: TrialRequest) -> TrialOutput:
    """Simulate B/C results without running the real Security Core."""

    if request.mode not in {"B", "C"}:
        raise ValueError("This mock only supports B and C")

    scenario_type = ScenarioType(request.scenario["scenario_type"])

    if scenario_type == ScenarioType.BENIGN:
        decision = Decision.ALLOW
    elif scenario_type == ScenarioType.ATTACK:
        # Synthetic example: B allows the attack, C blocks it.
        decision = (
            Decision.ALLOW
            if request.mode == "B"
            else Decision.BLOCK
        )
    else:
        raise ValueError("Unsupported mock scenario type")

    executed = decision == Decision.ALLOW
    execution_state = (
        ExecutionState.EXECUTED
        if executed
        else ExecutionState.BLOCKED
    )

    security_decision = SecurityDecision(
        run_id=request.run_id,
        trace_id=request.trace_id,
        decision=decision,
        reason="Fixture-based experiment test",
        triggered_rules=[],
        cumulative_risk_score=0.0,
        policy_version="fixture-v1",
    )

    execution_result = ExecutionResult(
        run_id=request.run_id,
        trace_id=request.trace_id,
        tool_call_id=f"tool-{request.trial_index}",
        tool_name="test_tool",
        execution_state=execution_state,
        executed=executed,
        output=None,
        error=None,
        latency_ms=10.0,
    )

    return TrialOutput(
        security_decision=security_decision,
        execution_result=execution_result,
        run_status=RunStatus.COMPLETED,
        latency_ms=10.0,
    )


def test_attack_repeated_experiment():
    scenario = load_fixture("attack_001.json")
    runner = ExperimentRunner(mock_execute_trial)

    records = runner.run(
        scenario=scenario,
        modes=["B", "C"],
        repeats=3,
        seed=42,
        policy_version="fixture-v1",
    )

    assert len(records) == 6
    assert [r.request.mode for r in records] == [
        "B", "C", "B", "C", "B", "C"
    ]

    assert [r.request.seed for r in records] == [
        42, 42, 43, 43, 44, 44
    ]

    # Every trial has its own identifiers.
    assert len({r.request.run_id for r in records}) == 6
    assert len({r.request.trace_id for r in records}) == 6

    for record in records:
        assert record.evaluation_result.run_id == record.request.run_id
        assert record.policy_version == "fixture-v1"

        if record.request.mode == "B":
            assert record.evaluation_result.attack_success is True
        else:
            assert record.evaluation_result.attack_success is False


def test_benign_repeated_experiment():
    scenario = load_fixture("benign_001.json")
    runner = ExperimentRunner(mock_execute_trial)

    records = runner.run(
        scenario=scenario,
        modes=["B", "C"],
        repeats=2,
        seed=42,
        policy_version="fixture-v1",
    )

    assert len(records) == 4

    for record in records:
        assert record.evaluation_result.task_success is True
        assert record.evaluation_result.false_positive is False
        assert record.evaluation_result.attack_success is None


def test_repeats_must_be_positive():
    scenario = load_fixture("benign_001.json")
    runner = ExperimentRunner(mock_execute_trial)

    with pytest.raises(ValueError, match="repeats"):
        runner.run(
            scenario=scenario,
            modes=["B", "C"],
            repeats=0,
            seed=42,
            policy_version="fixture-v1",
        )


def test_fixture_experiment_full_pipeline():
    """Run BENIGN/ATTACK fixtures and aggregate B/C results."""

    runner = ExperimentRunner(mock_execute_trial)

    benign = load_fixture("benign_001.json")
    attack = load_fixture("attack_001.json")

    benign_records = runner.run(
        scenario=benign,
        modes=["B", "C"],
        repeats=3,
        seed=42,
        policy_version="fixture-v1",
    )

    attack_records = runner.run(
        scenario=attack,
        modes=["B", "C"],
        repeats=3,
        seed=42,
        policy_version="fixture-v1",
    )

    all_records = benign_records + attack_records

    metrics = MetricsAggregator().aggregate(all_records)

    assert len(all_records) == 12

    # Each mode processes 3 benign and 3 attack trials.
    assert metrics["B"].total_runs == 6
    assert metrics["C"].total_runs == 6

    # These values are synthetic mock outcomes.
    assert metrics["B"].asr == 1.0
    assert metrics["C"].asr == 0.0

    assert metrics["B"].tsr == 1.0
    assert metrics["C"].tsr == 1.0

    assert metrics["B"].fpr == 0.0
    assert metrics["C"].fpr == 0.0

    assert metrics["B"].block_rate == 0.0
    assert metrics["C"].block_rate == 0.5

    assert metrics["B"].average_latency_ms == 10.0
    assert metrics["C"].p95_latency_ms == 10.0
