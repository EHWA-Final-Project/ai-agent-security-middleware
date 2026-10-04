import logging

from schemas.evidence import SecurityEvent
from schemas.runtime import ExecutionResult, RuntimeObservation
from schemas.security import SecurityDecision, SecurityResult

from runtime.ports import RunStatusUpdate

from .builder import EvidenceBuilder
from .repository import EvidenceRepository

logger = logging.getLogger(__name__)


class EvidenceCollector:
    """Receive Runtime/Security outputs and persist SecurityEvent evidence."""

    def __init__(
        self,
        repository: EvidenceRepository,
        builder: EvidenceBuilder | None = None,
    ) -> None:
        self.repository = repository
        self.builder = builder or EvidenceBuilder()

    def _save_event(self, event: SecurityEvent) -> None:
        try:
            self.repository.save_event(event)
        except Exception:
            logger.exception(
                "Failed to save evidence event: "
                "event_type=%s run_id=%s trace_id=%s",
                event.event_type,
                event.run_id,
                event.trace_id,
            )
            raise

    def _find_execution_scenario_id(
        self,
        result: ExecutionResult,
    ) -> str | None:
        if result.tool_call_id is None:
            logger.warning(
                "ExecutionResult has no tool_call_id; "
                "scenario_id cannot be linked: run_id=%s",
                result.run_id,
            )
            return None

        events = self.repository.list_events_by_run(result.run_id)

        for event in reversed(events):
            if (
                event.event_type
                != self.builder.EVENT_RUNTIME_OBSERVATION
            ):
                continue

            tool_candidate = event.payload.get("tool_candidate")

            if (
                isinstance(tool_candidate, dict)
                and tool_candidate.get("tool_call_id")
                == result.tool_call_id
            ):
                return event.scenario_id

        logger.warning(
            "No matching RuntimeObservation for ExecutionResult; "
            "saving with scenario_id=None: "
            "run_id=%s tool_call_id=%s",
            result.run_id,
            result.tool_call_id,
        )
        return None

    # Security Core → Evidence

    def record_result(self, result: SecurityResult) -> None:
        event = self.builder.from_security_result(result)
        self._save_event(event)

    def record_decision(self, decision: SecurityDecision) -> None:
        event = self.builder.from_security_decision(decision)
        self._save_event(event)

    # Runtime → Evidence

    def record_observation(
        self,
        observation: RuntimeObservation,
    ) -> None:
        event = self.builder.from_runtime_observation(observation)
        self._save_event(event)

    def record_execution(self, result: ExecutionResult) -> None:
        scenario_id = self._find_execution_scenario_id(result)

        event = self.builder.from_execution_result(
            result,
            scenario_id=scenario_id,
        )
        self._save_event(event)

    def record_run_status(self, update: RunStatusUpdate) -> None:
        event = self.builder.from_run_status(update)
        self._save_event(event)