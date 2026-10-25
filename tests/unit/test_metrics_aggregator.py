import pytest
from enums import Decision, ScenarioType
from schemas.evidence import EvaluationResult

from evaluation.experiment_runner import TrialRecord, TrialRequest
from evaluation.metrics_aggregator import MetricsAggregator


def make_record(
    *,
    mode: str,
    scenario_type: ScenarioType,
    decision: Decision,
    index: int,
    attack_success: bool | None = None,
    task_success: bool | None = None,
    false_positive: bool | None = None,
    latency_ms: float | None = None,
    policy_version: str = "fixture-v1",
) -> TrialRecord:
    scenario_id = f"{scenario_type.value}-{index}"
    run_id = f"run-{mode}-{scenario_id}"

    request = TrialRequest(
        scenario={"scenario_id": scenario_id},
        mode=mode,
        trial_index=index,
        run_id=run_id,
        trace_id=f"trace-{mode}-{scenario_id}",
        seed=42,
    )

    evaluation = EvaluationResult(
        scenario_id=scenario_id,
        run_id=run_id,
        scenario_type=scenario_type,
        expected_result={},
        actual_result={"final_decision": decision.value},
        attack_success=attack_success,
        task_success=task_success,
        false_positive=false_positive,
    )

    return TrialRecord(
        request=request,
        evaluation_result=evaluation,
        policy_version=policy_version,
        source="fixture",
        latency_ms=latency_ms,
    )


def test_metrics_aggregation():
    records = [
        make_record(
            mode="B", scenario_type=ScenarioType.ATTACK,
            decision=Decision.ALLOW, index=1,
            attack_success=True, latency_ms=10.0,
        ),
        make_record(
            mode="B", scenario_type=ScenarioType.ATTACK,
            decision=Decision.BLOCK, index=2,
            attack_success=False, latency_ms=20.0,
        ),
        make_record(
            mode="B", scenario_type=ScenarioType.ATTACK,
            decision=Decision.ALLOW, index=3,
            attack_success=True,
        ),
        make_record(
            mode="B", scenario_type=ScenarioType.BENIGN,
            decision=Decision.ALLOW, index=1,
            task_success=True, false_positive=False,
            latency_ms=30.0,
        ),
        make_record(
            mode="B", scenario_type=ScenarioType.BENIGN,
            decision=Decision.BLOCK, index=2,
            task_success=False, false_positive=True,
            latency_ms=40.0,
        ),
    ]

    metrics = MetricsAggregator().aggregate(records)["B"]

    assert metrics.total_runs == 5
    assert metrics.attack_scenarios == 3
    assert metrics.benign_scenarios == 2

    assert metrics.asr == pytest.approx(2 / 3)
    assert metrics.tsr == pytest.approx(0.5)
    assert metrics.fpr == pytest.approx(0.5)
    assert metrics.block_rate == pytest.approx(0.4)

    assert metrics.average_latency_ms == pytest.approx(25.0)
    assert metrics.p50_latency_ms == pytest.approx(25.0)
    assert metrics.p95_latency_ms == pytest.approx(38.5)
    assert metrics.policy_version == "fixture-v1"


def test_modes_are_aggregated_separately():
    records = [
        make_record(
            mode="B", scenario_type=ScenarioType.ATTACK,
            decision=Decision.ALLOW, index=1,
            attack_success=True,
        ),
        make_record(
            mode="C", scenario_type=ScenarioType.ATTACK,
            decision=Decision.BLOCK, index=1,
            attack_success=False,
        ),
    ]

    results = MetricsAggregator().aggregate(records)

    assert set(results) == {"B", "C"}
    assert results["B"].asr == 1.0
    assert results["C"].asr == 0.0


def test_no_attack_trials_returns_none():
    record = make_record(
        mode="B",
        scenario_type=ScenarioType.BENIGN,
        decision=Decision.ALLOW,
        index=1,
        task_success=True,
        false_positive=False,
    )

    metrics = MetricsAggregator().aggregate([record])["B"]

    assert metrics.asr is None
    assert metrics.tsr == 1.0
    assert metrics.average_latency_ms is None
    assert metrics.p50_latency_ms is None
    assert metrics.p95_latency_ms is None


def test_mixed_policy_versions_are_rejected():
    records = [
        make_record(
            mode="B", scenario_type=ScenarioType.ATTACK,
            decision=Decision.BLOCK, index=1,
            attack_success=False,
            policy_version="v1",
        ),
        make_record(
            mode="B", scenario_type=ScenarioType.ATTACK,
            decision=Decision.BLOCK, index=2,
            attack_success=False,
            policy_version="v2",
        ),
    ]

    with pytest.raises(ValueError, match="mixed policy versions"):
        MetricsAggregator().aggregate(records)
