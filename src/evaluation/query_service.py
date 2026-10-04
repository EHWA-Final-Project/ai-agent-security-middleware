from evidence.repository import EvidenceRepository

from .models import RunResultDTO, TraceResultDTO


class EvidenceQueryService:
    """Provides stable Evidence query results for Platform / Thin Query."""

    def __init__(self, repository: EvidenceRepository) -> None:
        self.repository = repository

    def get_run_result(self, run_id: str) -> RunResultDTO:
        events = self.repository.list_events_by_run(run_id)

        return RunResultDTO(
            run_id=run_id,
            events=events,
        )

    def get_trace_result(self, trace_id: str) -> TraceResultDTO:
        events = self.repository.list_events_by_trace(trace_id)

        return TraceResultDTO(
            trace_id=trace_id,
            events=events,
        )