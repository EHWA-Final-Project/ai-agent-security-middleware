import pytest
from enums import Decision, ExecutionState, RunStatus

from evidence.collector import EvidenceCollector
from evidence.sqlite_repository import SQLiteEvidenceRepository
from examples.custom_guard import CustomKeywordGuard
from runtime.adapter import RuntimeAdapter
from runtime.dto import RuntimeRequest, ToolRequest
from runtime.mock_tools.tools import MockReadFile
from security.orchestrator.orchestrator import SecurityOrchestrator
from security.plugins.manager import PluginManager
from security.policy.config import PolicyConfig


def make_custom_security_factory(policy, evidence_sink, *, enabled=True):
    def factory(enforcement):
        manager = PluginManager()
        manager.register_guard(CustomKeywordGuard(), enabled=enabled)

        return SecurityOrchestrator(
            plugin_manager=manager,
            policy_config=policy,
            enforcement=enforcement,
            evidence_sink=evidence_sink,
        )

    return factory


def run_custom_guard_scenario(tmp_path, *, enabled):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")
    collector = EvidenceCollector(repository)

    read_file = MockReadFile({"notes.txt": "hello"})

    request = RuntimeRequest(
        user_input="Please summarize restricted-demo-token.",
        context_items=[],
        session_id="session-custom-guard",
        scenario_id="CUSTOM-GUARD-001",
        tool_request=ToolRequest(
            tool_name="read_file",
            tool_arguments={"path": "notes.txt"},
        ),
    )

    policy = PolicyConfig(
        policy_version="custom-guard-runtime-test",
        strict_threshold=0.5,
        block_threshold=0.75,
    )

    result = RuntimeAdapter().run(
        request,
        tools={"read_file": read_file},
        evidence=collector,
        security_factory=make_custom_security_factory(
            policy,
            collector,
            enabled=enabled,
        ),
    )

    events = repository.list_events_by_run(result.identity.run_id)

    return result, read_file, events


def test_custom_guard_blocks_tool_before_execution(tmp_path):
    result, read_file, events = run_custom_guard_scenario(
        tmp_path,
        enabled=True,
    )

    assert result.run_status == RunStatus.COMPLETED
    assert result.decision.decision == Decision.BLOCK
    assert result.execution.execution_state == ExecutionState.BLOCKED
    assert result.execution.executed is False

    assert read_file.call_count == 0
    assert result.output_allowed is False

    guard_events = [
        event
        for event in events
        if event.event_type == "SECURITY_RESULT"
        and event.payload.get("guard_name") == "custom_keyword_guard"
    ]

    assert len(guard_events) == 1
    assert guard_events[0].payload["decision"] == "WARN"

    decision_events = [
        event
        for event in events
        if event.event_type == "SECURITY_DECISION"
    ]

    execution_events = [
        event
        for event in events
        if event.event_type == "EXECUTION_RESULT"
    ]

    assert decision_events
    assert execution_events

    assert decision_events[-1].payload["decision"] == "BLOCK"
    assert execution_events[-1].payload["executed"] is False


def test_disabled_custom_guard_allows_tool_execution(tmp_path):
    result, read_file, events = run_custom_guard_scenario(
        tmp_path,
        enabled=False,
    )

    assert result.run_status == RunStatus.COMPLETED
    assert result.decision.decision == Decision.ALLOW
    assert result.execution.execution_state == ExecutionState.EXECUTED
    assert result.execution.executed is True

    assert read_file.call_count == 1
    assert result.output_allowed is True

    guard_events = [
        event
        for event in events
        if event.event_type == "SECURITY_RESULT"
        and event.payload.get("guard_name") == "custom_keyword_guard"
    ]

    assert guard_events == []


@pytest.mark.parametrize("enabled", [True, False])
def test_custom_guard_evidence_identity_consistency(tmp_path, enabled):
    result, _, events = run_custom_guard_scenario(
        tmp_path,
        enabled=enabled,
    )

    assert events

    assert all(
        event.run_id == result.identity.run_id
        for event in events
    )

    assert all(
        event.trace_id == result.identity.trace_id
        for event in events
    )

    event_types = {event.event_type for event in events}

    assert "RUNTIME_OBSERVATION" in event_types
    assert "SECURITY_DECISION" in event_types
    assert "EXECUTION_RESULT" in event_types
    assert "RUN_STATUS" in event_types
