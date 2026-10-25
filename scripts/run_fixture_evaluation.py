
"""Fixture Evaluation Smoke - runnable experiment script (Wana's scope).

Run from the repository root in PowerShell:
    $env:PYTHONPATH = "src;shared"
    uv run python -m scripts.run_fixture_evaluation

Runs repeated BENIGN-001 and ATTACK-001 fixture experiments
under B (Independent) and C (Cross-layer) synthetic conditions.

Validates:
- Repeated scenario execution through ExperimentRunner
- Expected vs Actual evaluation using P0Evaluator
- ASR, TSR, FPR, Block Rate, and latency aggregation
- Mode-specific MetricsDTO generation

Prints JSON comparison results for B/C conditions.
"""

import json
from pathlib import Path

from enums import Decision, ExecutionState, RunStatus, ScenarioType
from schemas.runtime import ExecutionResult
from schemas.security import SecurityDecision

from evaluation.experiment_runner import (
    ExperimentRunner,
    TrialOutput,
    TrialRequest,
)
from evaluation.metrics_aggregator import MetricsAggregator

ROOT_DIR = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT_DIR / "shared" / "fixtures"


def load_fixture(filename: str) -> dict:
    path = FIXTURE_DIR / filename
    return json.loads(path.read_text(encoding="utf-8"))


def execute_fixture_trial(request: TrialRequest) -> TrialOutput:
    """Return synthetic execution results, not real Guard outputs."""

    if request.mode not in {"B", "C"}:
        raise ValueError("Only B and C are supported")

    scenario_type = ScenarioType(request.scenario["scenario_type"])

    if scenario_type == ScenarioType.BENIGN:
        decision = Decision.ALLOW
    elif scenario_type == ScenarioType.ATTACK:
        decision = (
            Decision.ALLOW
            if request.mode == "B"
            else Decision.BLOCK
        )
    else:
        raise ValueError("Unsupported fixture scenario")

    executed = decision == Decision.ALLOW

    security_decision = SecurityDecision(
        run_id=request.run_id,
        trace_id=request.trace_id,
        decision=decision,
        reason="Synthetic fixture evaluation",
        triggered_rules=[],
        cumulative_risk_score=0.0,
        policy_version="fixture-v1",
    )

    execution_result = ExecutionResult(
        run_id=request.run_id,
        trace_id=request.trace_id,
        tool_call_id=f"tool-{request.trial_index}",
        tool_name="test_tool",
        execution_state=(
            ExecutionState.EXECUTED
            if executed
            else ExecutionState.BLOCKED
        ),
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


def main() -> None:
    runner = ExperimentRunner(execute_fixture_trial)
    records = []

    scenario_files = [
        "benign_001.json",
        "attack_001.json",
    ]

    for filename in scenario_files:
        scenario = load_fixture(filename)

        records.extend(
            runner.run(
                scenario=scenario,
                modes=["B", "C"],
                repeats=3,
                seed=42,
                policy_version="fixture-v1",
                source="fixture",
            )
        )

    metrics = MetricsAggregator().aggregate(records)
    
    checks = {
        "12 fixture trials generated": len(records) == 12,
        "B/C modes available": set(metrics) == {"B", "C"},
        "Unique run_id per trial": (
            len({r.request.run_id for r in records}) == len(records)
        ),
        "Unique trace_id per trial": (
            len({r.request.trace_id for r in records}) == len(records)
        ),
        "Metrics generated for all modes": all(
            result.total_runs == 6
            for result in metrics.values()
        ),
    }


    report = {
        "source": "FIXTURE / MOCK",
        "warning": "NOT real Guard performance measurements",
        "scenarios": scenario_files,
        "modes": ["B", "C"],
        "repeats_per_scenario_per_mode": 3,
        "seed": 42,
        "total_trials": len(records),
        "metrics": {
            mode: result.model_dump(mode="json")
            for mode, result in metrics.items()
        },
    }

    
    print(json.dumps(report, indent=2))

    print("\nFixture Evaluation Smoke Checklist")
    for name, passed in checks.items():
        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {name}")

    if not all(checks.values()):
        raise SystemExit(1)



if __name__ == "__main__":
    main()
