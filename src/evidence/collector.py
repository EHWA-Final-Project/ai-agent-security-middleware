from schemas.runtime import ExecutionResult, RuntimeObservation
from schemas.security import SecurityDecision, SecurityResult

from runtime.ports import RunStatusUpdate

from .builder import EvidenceBuilder
from .repository import EvidenceRepository


class EvidenceCollector:
    """Receive Runtime/Security outputs and persist SecurityEvent evidence."""

    def __init__(
        self,
        repository: EvidenceRepository,
        builder: EvidenceBuilder | None = None,
    ) -> None:
        self.repository = repository
        self.builder = builder or EvidenceBuilder()

    # Security Core → Evidence

    def record_result(self, result: SecurityResult) -> None:
        event = self.builder.from_security_result(result)
        self.repository.save_event(event)

    def record_decision(self, decision: SecurityDecision) -> None:
        event = self.builder.from_security_decision(decision)
        self.repository.save_event(event)

    # Runtime → Evidence

    def record_observation(self, observation: RuntimeObservation) -> None:
        event = self.builder.from_runtime_observation(observation)
        self.repository.save_event(event)

    def record_execution(self, result: ExecutionResult) -> None:
        event = self.builder.from_execution_result(result)
        self.repository.save_event(event)

    def record_run_status(self, update: RunStatusUpdate) -> None:
        event = self.builder.from_run_status(update)
        self.repository.save_event(event)