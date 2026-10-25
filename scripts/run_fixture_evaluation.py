
"""Fixture Evaluation Smoke - runnable experiment script (Wana's scope).

Run from the repository root in PowerShell:
    $env:PYTHONPATH = ".;src;shared"
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

import csv
import json
import platform
from datetime import UTC, datetime
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

OUTPUT_DIR = ROOT_DIR / "reports" / "fixture_evaluation"


def percent(value: float | None) -> str:
    if value is None:
        return "N/A"
    return f"{value * 100:.1f}%"


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

    # Track the sample counts for each condition.
    sample_counts = {}

    for mode in ("B", "C"):
        mode_records = [
            record for record in records
            if record.request.mode == mode
        ]

        sample_counts[mode] = {
            "total_trials": len(mode_records),
            "attack_trials": metrics[mode].attack_scenarios,
            "benign_trials": metrics[mode].benign_scenarios,
            "latency_samples": sum(
                record.latency_ms is not None
                for record in mode_records
            ),
            "completed_trials": sum(
                record.evaluation_result.actual_result["run_status"]
                == "COMPLETED"
                for record in mode_records
            ),
        }

    # Keep trial-level data for reproducibility.
    trials = []

    for record in records:
        evaluation = record.evaluation_result
        request = record.request

        trials.append({
            "scenario_id": evaluation.scenario_id,
            "mode": request.mode,
            "trial_index": request.trial_index,
            "run_id": request.run_id,
            "trace_id": request.trace_id,
            "seed": request.seed,
            "policy_version": record.policy_version,
            "source": record.source,
            "latency_ms": record.latency_ms,
            "expected_result": evaluation.expected_result,
            "actual_result": evaluation.actual_result,
            "attack_success": evaluation.attack_success,
            "task_success": evaluation.task_success,
            "false_positive": evaluation.false_positive,
        })

    report = {
        "source": "FIXTURE / MOCK",
        "warning": "NOT real Guard performance measurements",
        "created_at_utc": datetime.now(UTC).isoformat(),
        "environment": {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
        },
        "experiment": {
            "scenarios": scenario_files,
            "modes": ["B", "C"],
            "repeats_per_scenario_per_mode": 3,
            "seed": 42,
            "total_trials": len(records),
            "policy_versions": {
                mode: result.policy_version
                for mode, result in metrics.items()
            },
            "latency_scope": "synthetic fixed 10 ms per trial",
            "failure_policy": (
                "Fail-fast: invalid or incomplete trials abort "
                "the batch instead of being silently excluded"
            ),
        },
        "sample_counts": sample_counts,
        "metrics": {
            mode: result.model_dump(mode="json")
            for mode, result in metrics.items()
        },
        "trials": trials,
    }

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
        "All trials completed": all(
            counts["completed_trials"] == counts["total_trials"]
            for counts in sample_counts.values()
        ),
    }

    print("\nFixture Evaluation Smoke Checklist")
    for name, passed in checks.items():
        print(f"[{'PASS' if passed else 'FAIL'}] {name}")

    if not all(checks.values()):
        raise SystemExit(1)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Export complete metadata and individual trial results.
    json_path = OUTPUT_DIR / "fixture_bc_report.json"
    json_path.write_text(
        json.dumps(report, indent=2, default=str),
        encoding="utf-8",
    )

    # Export numeric metrics for comparison and graphs.
    csv_path = OUTPUT_DIR / "fixture_bc_metrics.csv"

    fieldnames = [
        "mode",
        "total_runs",
        "attack_trials",
        "benign_trials",
        "latency_samples",
        "asr",
        "tsr",
        "fpr",
        "block_rate",
        "average_latency_ms",
        "p50_latency_ms",
        "p95_latency_ms",
        "policy_version",
    ]

    rows = []

    for mode, result in metrics.items():
        rows.append({
            "mode": mode,
            "total_runs": result.total_runs,
            "attack_trials": result.attack_scenarios,
            "benign_trials": result.benign_scenarios,
            "latency_samples": sample_counts[mode]["latency_samples"],
            "asr": result.asr,
            "tsr": result.tsr,
            "fpr": result.fpr,
            "block_rate": result.block_rate,
            "average_latency_ms": result.average_latency_ms,
            "p50_latency_ms": result.p50_latency_ms,
            "p95_latency_ms": result.p95_latency_ms,
            "policy_version": result.policy_version,
        })

    with csv_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print("\nB/C Comparison (SYNTHETIC FIXTURE RESULTS)")
    print("Metric          B           C")
    print("--------------------------------")

    for label, attribute in [
        ("ASR", "asr"),
        ("TSR", "tsr"),
        ("FPR", "fpr"),
        ("Block Rate", "block_rate"),
    ]:
        b = percent(getattr(metrics["B"], attribute))
        c = percent(getattr(metrics["C"], attribute))
        print(f"{label:<15} {b:<11} {c}")

    print("\nReports saved:")
    print(json_path)
    print(csv_path)
    print("\nWARNING: These are synthetic, not real Guard results.")


if __name__ == "__main__":
    main()

