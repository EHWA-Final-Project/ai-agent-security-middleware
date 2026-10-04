from abc import ABC, abstractmethod

from schemas.evidence import SecurityEvent


class EvidenceRepository(ABC):
    """Storage contract from the frozen Interface Draft."""

    @abstractmethod
    def save_event(self, event: SecurityEvent) -> None:
        raise NotImplementedError

    @abstractmethod
    def list_events_by_run(self, run_id: str) -> list[SecurityEvent]:
        raise NotImplementedError

    @abstractmethod
    def list_events_by_trace(self, trace_id: str) -> list[SecurityEvent]:
        raise NotImplementedError

    @abstractmethod
    def list_events_by_scenario(self, scenario_id: str) -> list[SecurityEvent]:
        raise NotImplementedError
