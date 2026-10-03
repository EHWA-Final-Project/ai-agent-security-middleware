"""로컬 M1 연결 계약 초안. 실제 서명은 Fatin/Wana와 검토한다."""

from datetime import datetime
from typing import Protocol

from enums import RunStatus
from errors import ErrorDetail
from schemas import (
    ExecutionResult,
    RuntimeObservation,
    SecurityDecision,
)

from runtime.dto import RuntimeDTO


class RunStatusUpdate(RuntimeDTO):
    run_id: str
    trace_id: str
    run_status: RunStatus
    error: ErrorDetail | None
    updated_at: datetime


class SecurityPort(Protocol):
    def evaluate(
        self,
        observation: RuntimeObservation,
    ) -> SecurityDecision: ...


class EvidencePort(Protocol):
    def record_observation(
        self,
        observation: RuntimeObservation,
    ) -> None: ...

    def record_execution(
        self,
        result: ExecutionResult,
    ) -> None: ...

    def record_run_status(
        self,
        update: RunStatusUpdate,
    ) -> None: ...
