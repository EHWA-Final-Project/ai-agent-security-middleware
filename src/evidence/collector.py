from schemas.security import SecurityDecision, SecurityResult

from .builder import EvidenceBuilder
from .repository import EvidenceRepository


class EvidenceCollector:
    """Receives Security Core outputs and persists them as SecurityEvent evidence."""

    def __init__(
        self,
        repository: EvidenceRepository,
        builder: EvidenceBuilder | None = None,
    ) -> None:
        self.repository = repository
        self.builder = builder or EvidenceBuilder()

    def record_result(self, result: SecurityResult) -> None:
        event = self.builder.from_security_result(result)
        self.repository.save_event(event)

    def record_decision(self, decision: SecurityDecision) -> None:
        event = self.builder.from_security_decision(decision)
        self.repository.save_event(event)