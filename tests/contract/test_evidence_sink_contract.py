from enums import Decision, GuardExecutionStatus, Stage
from schemas.security import SecurityDecision, SecurityResult

from evidence.collector import EvidenceCollector
from evidence.sqlite_repository import SQLiteEvidenceRepository


def test_real_security_result_is_recorded_as_evidence(tmp_path):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")
    collector = EvidenceCollector(repository)

    result = SecurityResult(
        run_id="run-attack-001",
        trace_id="trace-attack-001",
        stage=Stage.CONTEXT,
        guard_name="context_guard",
        execution_status=GuardExecutionStatus.SUCCESS,
        risk_score=0.65,
        decision=Decision.WARN,
        rule_ids=["CTX-INJECTION-001"],
        evidence=[
            {
                "message": "malicious instruction detected",
            }
        ],
        latency_ms=2.4,
        error=None,
    )

    collector.record_result(result)

    stored = repository.list_events_by_run("run-attack-001")

    assert len(stored) == 1
    assert stored[0].trace_id == "trace-attack-001"
    assert stored[0].event_type == "SECURITY_RESULT"
    assert stored[0].stage == Stage.CONTEXT
    assert stored[0].payload["decision"] == "WARN"
    assert stored[0].payload["risk_score"] == 0.65
    assert stored[0].payload["latency_ms"] == 2.4


def test_real_security_decision_is_recorded_as_evidence(tmp_path):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")
    collector = EvidenceCollector(repository)

    decision = SecurityDecision(
        run_id="run-attack-001",
        trace_id="trace-attack-001",
        decision=Decision.BLOCK,
        reason="Tool misuse blocked",
        triggered_rules=["TOOL-DENY-001"],
        cumulative_risk_score=0.85,
        policy_version="p0-v1",
        sanitized_output=None,
    )

    collector.record_decision(decision)

    stored = repository.list_events_by_trace("trace-attack-001")

    assert len(stored) == 1
    assert stored[0].run_id == "run-attack-001"
    assert stored[0].event_type == "SECURITY_DECISION"
    assert stored[0].payload["decision"] == "BLOCK"
    assert stored[0].payload["triggered_rules"] == ["TOOL-DENY-001"]