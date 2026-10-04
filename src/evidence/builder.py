from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from enums import Stage
from pydantic import BaseModel
from schemas.evidence import SecurityEvent
from schemas.runtime import ExecutionResult, RuntimeObservation
from schemas.security import SecurityDecision, SecurityResult


class EvidenceBuilder:
    """Normalize Runtime/Security outputs into common SecurityEvent evidence."""

    EVENT_RUNTIME_OBSERVATION = "RUNTIME_OBSERVATION"
    EVENT_SECURITY_RESULT = "SECURITY_RESULT"
    EVENT_SECURITY_DECISION = "SECURITY_DECISION"
    EVENT_EXECUTION_RESULT = "EXECUTION_RESULT"
    EVENT_RUN_STATUS = "RUN_STATUS"

    @staticmethod
    def _normalize_stage(value: Any) -> Stage | None:
        if value is None:
            return None
        if isinstance(value, Stage):
            return value
        return Stage(str(value))

    @staticmethod
    def _to_payload(
        source: BaseModel | Mapping[str, Any],
    ) -> dict[str, Any]:
        if isinstance(source, BaseModel):
            return source.model_dump(mode="json")

        return dict(source)

    def build(
        self,
        *,
        source: BaseModel | Mapping[str, Any],
        event_type: str,
        scenario_id: str | None = None,
        stage: Stage | str | None = None,
    ) -> SecurityEvent:
        payload = self._to_payload(source)

        run_id = str(payload["run_id"])
        trace_id = str(payload["trace_id"])

        source_stage = stage if stage is not None else payload.get("stage")

        return SecurityEvent(
            event_id=f"evt-{uuid4()}",
            run_id=run_id,
            trace_id=trace_id,
            scenario_id=(
                scenario_id
                if scenario_id is not None
                else payload.get("scenario_id")
            ),
            event_type=event_type,
            stage=self._normalize_stage(source_stage),
            payload=payload,
            created_at=datetime.now(UTC),
        )

    def from_runtime_observation(
        self,
        source: RuntimeObservation,
        *,
        scenario_id: str | None = None,
    ) -> SecurityEvent:
        return self.build(
            source=source,
            event_type=self.EVENT_RUNTIME_OBSERVATION,
            scenario_id=scenario_id,
        )

    def from_security_result(
        self,
        source: SecurityResult,
        *,
        scenario_id: str | None = None,
    ) -> SecurityEvent:
        return self.build(
            source=source,
            event_type=self.EVENT_SECURITY_RESULT,
            scenario_id=scenario_id,
        )

    def from_security_decision(
        self,
        source: SecurityDecision,
        *,
        scenario_id: str | None = None,
        stage: Stage | str | None = None,
    ) -> SecurityEvent:
        return self.build(
            source=source,
            event_type=self.EVENT_SECURITY_DECISION,
            scenario_id=scenario_id,
            stage=stage,
        )

    def from_execution_result(
        self,
        source: ExecutionResult,
        *,
        scenario_id: str | None = None,
        stage: Stage | str | None = None,
    ) -> SecurityEvent:
        return self.build(
            source=source,
            event_type=self.EVENT_EXECUTION_RESULT,
            scenario_id=scenario_id,
            stage=stage,
        )
    def from_run_status(
    self,
    source: BaseModel,
    *,
    scenario_id: str | None = None,
    ) -> SecurityEvent:
       return self.build(
        source=source,
        event_type=self.EVENT_RUN_STATUS,
        scenario_id=scenario_id,
       )    