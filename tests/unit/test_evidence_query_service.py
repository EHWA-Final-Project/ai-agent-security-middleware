from datetime import UTC, datetime

from enums import Stage
from schemas.evidence import SecurityEvent

from evaluation import EvidenceQueryService
from evidence.sqlite_repository import SQLiteEvidenceRepository


def make_event() -> SecurityEvent:
    return SecurityEvent(
        event_id="evt-query-001",
        run_id="run-query-001",
        trace_id="trace-query-001",
        scenario_id="BENIGN-001",
        event_type="SECURITY_RESULT",
        stage=Stage.TOOL,
        payload={"decision": "ALLOW"},
        created_at=datetime.now(UTC),
    )


def test_query_result_by_run_id(tmp_path):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")
    service = EvidenceQueryService(repository)

    repository.save_event(make_event())

    result = service.get_run_result("run-query-001")

    assert result.run_id == "run-query-001"
    assert len(result.events) == 1
    assert result.events[0].trace_id == "trace-query-001"


def test_query_result_by_trace_id(tmp_path):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")
    service = EvidenceQueryService(repository)

    repository.save_event(make_event())

    result = service.get_trace_result("trace-query-001")

    assert result.trace_id == "trace-query-001"
    assert len(result.events) == 1
    assert result.events[0].run_id == "run-query-001"


def test_unknown_run_and_trace_return_empty_results(tmp_path):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")
    service = EvidenceQueryService(repository)

    run_result = service.get_run_result("missing-run")
    trace_result = service.get_trace_result("missing-trace")

    assert run_result.events == []
    assert trace_result.events == []