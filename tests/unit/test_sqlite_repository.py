from datetime import UTC, datetime

from enums import Stage
from schemas.evidence import SecurityEvent

from evidence.sqlite_repository import SQLiteEvidenceRepository


def make_event() -> SecurityEvent:
    return SecurityEvent(
        event_id="evt-unit-001",
        run_id="run-unit-001",
        trace_id="trace-unit-001",
        scenario_id="BENIGN-001",
        event_type="SECURITY_RESULT",
        stage=Stage.TOOL,
        payload={"decision": "ALLOW", "risk_score": 0.1},
        created_at=datetime.now(UTC),
    )


def test_save_and_query_by_run_trace_and_scenario(tmp_path):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")
    event = make_event()

    repository.save_event(event)

    by_run = repository.list_events_by_run("run-unit-001")
    by_trace = repository.list_events_by_trace("trace-unit-001")
    by_scenario = repository.list_events_by_scenario("BENIGN-001")

    assert len(by_run) == 1
    assert len(by_trace) == 1
    assert len(by_scenario) == 1
    assert by_run[0].event_id == event.event_id
    assert by_run[0].payload["decision"] == "ALLOW"


def test_duplicate_event_id_is_idempotent(tmp_path):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")
    event = make_event()

    repository.save_event(event)
    repository.save_event(event)

    assert len(repository.list_events_by_run(event.run_id)) == 1