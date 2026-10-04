from schemas.evidence import EvaluationResult as SharedEvaluationResult

from evaluation import EvaluationResult, MetricsDTO


def test_evaluation_result_uses_shared_schema():
    assert EvaluationResult is SharedEvaluationResult


def test_minimal_metrics_dto_can_be_created():
    metrics = MetricsDTO(
        experiment_condition="baseline",
        total_runs=1,
        attack_scenarios=1,
        benign_scenarios=0,
    )

    assert metrics.total_runs == 1
    assert metrics.asr is None
    assert metrics.tsr is None
    assert metrics.fpr is None