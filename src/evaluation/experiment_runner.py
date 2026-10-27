
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from enums import RunStatus
from schemas.evidence import EvaluationResult
from schemas.runtime import ExecutionResult
from schemas.security import SecurityDecision

from .evaluator import P0Evaluator


@dataclass(frozen=True)
class TrialRequest:
    scenario: Mapping[str, Any]
    mode: str
    trial_index: int
    run_id: str
    trace_id: str
    seed: int


@dataclass(frozen=True)
class TrialOutput:
    security_decision: SecurityDecision
    execution_result: ExecutionResult
    run_status: RunStatus
    latency_ms: float | None = None


@dataclass(frozen=True)
class TrialRecord:
    request: TrialRequest
    evaluation_result: EvaluationResult
    policy_version: str
    source: str
    latency_ms: float | None


class ExperimentRunner:
    """Run scenarios repeatedly and collect P0 evaluation results."""

    def __init__(
        self,
        execute_trial: Callable[[TrialRequest], TrialOutput],
    ) -> None:
        self.execute_trial = execute_trial
        self.evaluator = P0Evaluator()

    def run(
        self,
        *,
        scenario: Mapping[str, Any],
        modes: Sequence[str],
        repeats: int,
        seed: int,
        policy_version: str,
        source: str = "fixture",
    ) -> list[TrialRecord]:
        if repeats < 1:
            raise ValueError("repeats must be at least 1")

        if not modes:
            raise ValueError("at least one mode is required")

        records: list[TrialRecord] = []

        for trial_index in range(1, repeats + 1):
            trial_seed = seed + trial_index - 1

            for mode in modes:
                request = TrialRequest(
                    scenario=scenario,
                    mode=mode,
                    trial_index=trial_index,
                    run_id=str(uuid4()),
                    trace_id=str(uuid4()),
                    seed=trial_seed,
                )

                output = self.execute_trial(request)
                
                # Verify that the executed policy matches the experiment.
                if output.security_decision.policy_version != policy_version:
                    raise ValueError(
                        "trial policy_version mismatch"
                    )

                # Incomplete trials must not be counted as completed.
                if output.run_status != RunStatus.COMPLETED:
                    raise ValueError(
                        f"trial did not complete: {output.run_status.value}"
                    )


                # All results must belong to this exact trial.
                for result in (
                    output.security_decision,
                    output.execution_result,
                ):
                    if result.run_id != request.run_id:
                        raise ValueError("trial run_id mismatch")
                    if result.trace_id != request.trace_id:
                        raise ValueError("trial trace_id mismatch")

                if (
                    output.latency_ms is not None
                    and output.latency_ms < 0
                ):
                    raise ValueError("latency_ms cannot be negative")

                evaluation = self.evaluator.evaluate(
                    scenario=scenario,
                    security_decision=output.security_decision,
                    execution_result=output.execution_result,
                    run_status=output.run_status,
                )

                records.append(
                    TrialRecord(
                        request=request,
                        evaluation_result=evaluation,
                        policy_version=policy_version,
                        source=source,
                        latency_ms=output.latency_ms,
                    )
                )

        return records
