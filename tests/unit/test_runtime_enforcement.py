import pytest
from enums import Decision, ExecutionState
from schemas import SecurityDecision

from runtime.adapter import RuntimeAdapter
from runtime.dto import RuntimeRequest, ToolRequest
from runtime.enforcement import Enforcement, EnforcementContractError
from runtime.mock_tools.tools import MockReadFile, MockSendEmail


def prepare(tool_name="send_email"):
    arguments = (
        {"path": "documents/meeting.txt"}
        if tool_name == "read_file"
        else {
            "to": ["review@example.invalid"],
            "subject": "테스트",
            "body": "합성 데이터",
        }
    )
    request = RuntimeRequest(
        user_input="회의록을 확인해줘",
        context_items=[],
        session_id=None,
        scenario_id=None,
        tool_request=ToolRequest(
            tool_name=tool_name,
            tool_arguments=arguments,
        ),
    )
    adapter = RuntimeAdapter()
    identity = adapter.create_identity(None, None)
    return adapter.prepare_tool_call(request, identity)


def decide(prepared, value):
    return SecurityDecision(
        run_id=prepared.observation.run_id,
        trace_id=prepared.observation.trace_id,
        decision=value,
        reason="테스트용 고정 판단",
        triggered_rules=[],
        cumulative_risk_score=0.0,
        policy_version="mock-v1",
    )


@pytest.mark.parametrize("tool_name", ["read_file", "send_email"])
def test_allow_executes_tool_once(tool_name):
    read = MockReadFile({"documents/meeting.txt": "회의록"})
    email = MockSendEmail()
    tools = {"read_file": read, "send_email": email}
    enforcement = Enforcement(tools)
    prepared = prepare(tool_name)

    result = enforcement.enforce(prepared, decide(prepared, Decision.ALLOW))

    assert tools[tool_name].call_count == 1
    assert result.execution_state == ExecutionState.EXECUTED
    assert result.executed is True
    assert result.error is None
    assert result.latency_ms >= 0
    assert result.tool_call_id == prepared.candidate.tool_call_id
    assert result.run_id == prepared.observation.run_id
    assert result.trace_id == prepared.observation.trace_id

    if tool_name == "read_file":
        assert result.output["content"] == "회의록"
    else:
        assert len(email.outbox) == 1


def test_block_never_calls_tool():
    email = MockSendEmail()
    enforcement = Enforcement({"send_email": email})
    prepared = prepare()

    result = enforcement.enforce(prepared, decide(prepared, Decision.BLOCK))

    assert email.call_count == 0
    assert email.outbox == []
    assert result.execution_state == ExecutionState.BLOCKED
    assert result.executed is False
    assert result.output is None
    assert result.error is None
    assert result.latency_ms == 0.0


def test_warn_does_not_execute():
    email = MockSendEmail()
    enforcement = Enforcement({"send_email": email})
    prepared = prepare()

    with pytest.raises(EnforcementContractError):
        enforcement.enforce(prepared, decide(prepared, Decision.WARN))

    assert email.call_count == 0
    assert email.outbox == []


@pytest.mark.parametrize("field", ["run_id", "trace_id"])
def test_wrong_decision_id_does_not_execute(field):
    email = MockSendEmail()
    enforcement = Enforcement({"send_email": email})
    prepared = prepare()
    decision = decide(prepared, Decision.ALLOW)
    setattr(decision, field, "different-id")

    with pytest.raises(EnforcementContractError, match="ID"):
        enforcement.enforce(prepared, decision)

    assert email.call_count == 0


def test_changed_candidate_does_not_execute():
    email = MockSendEmail()
    enforcement = Enforcement({"send_email": email})
    prepared = prepare()
    decision = decide(prepared, Decision.ALLOW)
    prepared.candidate.tool_arguments["body"] = "변경된 내용"

    with pytest.raises(EnforcementContractError, match="후보"):
        enforcement.enforce(prepared, decision)

    assert email.call_count == 0


def test_duplicate_call_does_not_send_twice():
    email = MockSendEmail()
    enforcement = Enforcement({"send_email": email})
    prepared = prepare()
    decision = decide(prepared, Decision.ALLOW)

    enforcement.enforce(prepared, decision)

    with pytest.raises(EnforcementContractError, match="이미"):
        enforcement.enforce(prepared, decision)

    assert email.call_count == 1
    assert len(email.outbox) == 1


def test_tool_error_is_failed_not_blocked():
    read = MockReadFile({})
    enforcement = Enforcement({"read_file": read})
    prepared = prepare("read_file")

    result = enforcement.enforce(prepared, decide(prepared, Decision.ALLOW))

    assert read.call_count == 1
    assert result.execution_state == ExecutionState.FAILED
    assert result.executed is True
    assert result.output is None
    assert result.error.code == "TOOL_EXECUTION_ERROR"
    assert result.latency_ms >= 0


def test_unknown_tool_fails_before_execution():
    enforcement = Enforcement({})
    prepared = prepare()

    result = enforcement.enforce(prepared, decide(prepared, Decision.ALLOW))

    assert result.execution_state == ExecutionState.FAILED
    assert result.executed is False
    assert result.error.code == "UNKNOWN_TOOL"
