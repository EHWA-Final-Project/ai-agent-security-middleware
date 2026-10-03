"""로컬 M1용 동기식 Tool 실행 경계."""

from datetime import UTC, datetime
from time import perf_counter
from typing import Any, Protocol

from enums import Decision, ExecutionState, Stage
from errors import ErrorDetail
from schemas import (
    ExecutionResult,
    SecurityDecision,
)

from runtime.dto import PreparedToolCall, ToolCandidate


class ToolExecutor(Protocol):
    def execute(self, candidate: ToolCandidate) -> dict[str, Any]: ...


class EnforcementContractError(ValueError):
    """실행 전 계약 위반. 보안 정책 BLOCK과 구분한다."""


class Enforcement:
    def __init__(self, tools: dict[str, ToolExecutor]) -> None:
        self._tools = dict(tools)
        self._handled: set[tuple[str, str]] = set()

    def enforce(
        self,
        prepared: PreparedToolCall,
        decision: SecurityDecision,
    ) -> ExecutionResult:
        observation = prepared.observation
        candidate = prepared.candidate.model_copy(deep=True)

        if observation.stage != Stage.TOOL:
            raise EnforcementContractError("TOOL 단계만 실행할 수 있습니다.")

        if (
            observation.run_id != decision.run_id
            or observation.trace_id != decision.trace_id
        ):
            raise EnforcementContractError("Decision ID 불일치")

        if observation.tool_candidate != candidate.model_dump():
            raise EnforcementContractError("Tool 후보 불일치")

        if decision.decision not in (Decision.ALLOW, Decision.BLOCK):
            raise EnforcementContractError("ALLOW/BLOCK 확정 판단이 필요합니다.")

        key = (observation.run_id, candidate.tool_call_id)
        if key in self._handled:
            raise EnforcementContractError("이미 처리한 Tool 호출입니다.")

        # 실행 오류나 BLOCK도 동일 호출을 자동 재처리하지 않는다.
        self._handled.add(key)

        common = {
            "run_id": observation.run_id,
            "trace_id": observation.trace_id,
            "tool_call_id": candidate.tool_call_id,
            "tool_name": candidate.tool_name,
        }

        if decision.decision == Decision.BLOCK:
            return ExecutionResult(
                **common,
                execution_state=ExecutionState.BLOCKED,
                executed=False,
                output=None,
                error=None,
                latency_ms=0.0,
            )

        tool = self._tools.get(candidate.tool_name)
        if tool is None:
            return ExecutionResult(
                **common,
                execution_state=ExecutionState.FAILED,
                executed=False,
                output=None,
                error=self._error(
                    "UNKNOWN_TOOL",
                    "등록되지 않은 Tool입니다.",
                    observation.trace_id,
                ),
                latency_ms=0.0,
            )

        started = perf_counter()
        try:
            output = tool.execute(candidate)
        # Tool 경계에서 일반 실행 오류를 FAILED 결과로 변환한다.
        except Exception as exc:  # noqa: BLE001
            elapsed_ms = (perf_counter() - started) * 1000
            return ExecutionResult(
                **common,
                execution_state=ExecutionState.FAILED,
                executed=True,
                output=None,
                error=self._error(
                    "TOOL_EXECUTION_ERROR",
                    "Mock Tool 실행 중 오류가 발생했습니다.",
                    observation.trace_id,
                    {"exception_type": type(exc).__name__},
                ),
                latency_ms=elapsed_ms,
            )

        elapsed_ms = (perf_counter() - started) * 1000
        return ExecutionResult(
            **common,
            execution_state=ExecutionState.EXECUTED,
            executed=True,
            output=output,
            error=None,
            latency_ms=elapsed_ms,
        )

    @staticmethod
    def _error(
        code: str,
        message: str,
        trace_id: str,
        details: dict[str, Any] | None = None,
    ) -> ErrorDetail:
        return ErrorDetail(
            code=code,
            message=message,
            stage=Stage.TOOL,
            retryable=False,
            details=details,
            timestamp=datetime.now(UTC),
            trace_id=trace_id,
        )
