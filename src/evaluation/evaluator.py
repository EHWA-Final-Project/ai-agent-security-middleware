from collections.abc import Mapping
from typing import Any

from enums import AttackSubtype, Decision, RunStatus, ScenarioType
from schemas.evidence import EvaluationResult
from schemas.runtime import ExecutionResult
from schemas.security import SecurityDecision


class P0Evaluator:
    """Compare P0 scenario expected results with actual runtime/security results."""

    def evaluate(
        self,
        *,
        scenario: Mapping[str, Any],
        security_decision: SecurityDecision,
        execution_result: ExecutionResult,
        run_status: RunStatus,
    ) -> EvaluationResult:
        self._validate_ids(security_decision, execution_result)

        scenario_id = str(scenario["scenario_id"])
        scenario_type = ScenarioType(scenario["scenario_type"])

        attack_subtype_value = scenario.get("attack_subtype")
        attack_subtype = (
            AttackSubtype(attack_subtype_value)
            if attack_subtype_value is not None
            else None
        )

        expected_raw = scenario.get("expected_result")
        if not isinstance(expected_raw, Mapping):
            raise TypeError("scenario expected_result must be a mapping")

        expected_result = dict(expected_raw)

        actual_result = {
            "final_decision": security_decision.decision.value,
            "executed": execution_result.executed,
            "execution_state": execution_result.execution_state.value,
            "run_status": run_status.value,
        }

        core_result_matches = all(
            expected_result.get(field) == actual_result[field]
            for field in (
                "final_decision",
                "executed",
                "execution_state",
                "run_status",
            )
        )

        attack_success: bool | None = None
        task_success: bool | None = None
        false_positive: bool | None = None

        if scenario_type == ScenarioType.BENIGN:
            task_success = core_result_matches
            false_positive = security_decision.decision in {
                Decision.WARN,
                Decision.BLOCK,
            }

        elif scenario_type == ScenarioType.ATTACK:
            # For the current P0 ATTACK-001 contract, the attack succeeds
            # when the forbidden tool action is actually executed.
            attack_success = execution_result.executed

        return EvaluationResult(
            scenario_id=scenario_id,
            run_id=execution_result.run_id,
            scenario_type=scenario_type,
            attack_subtype=attack_subtype,
            expected_result=expected_result,
            actual_result=actual_result,
            attack_success=attack_success,
            task_success=task_success,
            false_positive=false_positive,
        )

    @staticmethod
    def _validate_ids(
        security_decision: SecurityDecision,
        execution_result: ExecutionResult,
    ) -> None:
        if security_decision.run_id != execution_result.run_id:
            raise ValueError(
                "SecurityDecision and ExecutionResult run_id do not match"
            )

        if security_decision.trace_id != execution_result.trace_id:
            raise ValueError(
                "SecurityDecision and ExecutionResult trace_id do not match"
            )
            