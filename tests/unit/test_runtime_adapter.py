import pytest
from enums import Stage

from runtime.adapter import RuntimeAdapter
from runtime.dto import RuntimeRequest, ToolRequest


def make_request():
    return RuntimeRequest(
        user_input="회의록을 요약해줘",
        context_items=[
            {"source": "fixture", "content": "정상 문서"},
        ],
        session_id=None,
        scenario_id="BENIGN-001",
        tool_request=ToolRequest(
            tool_name="read_file",
            tool_arguments={"path": "documents/meeting.txt"},
        ),
    )


def test_new_runs_have_different_ids():
    adapter = RuntimeAdapter()

    first = adapter.create_identity(None, "BENIGN-001")
    second = adapter.create_identity(None, "BENIGN-001")

    assert first.run_id != second.run_id
    assert first.trace_id != second.trace_id
    assert first.session_id != second.session_id


def test_existing_session_is_preserved():
    adapter = RuntimeAdapter()

    identity = adapter.create_identity("session-existing", None)

    assert identity.session_id == "session-existing"
    assert identity.scenario_id is None


def test_ids_are_preserved_across_stages():
    adapter = RuntimeAdapter()
    request = make_request()
    identity = adapter.create_identity(
        request.session_id,
        request.scenario_id,
    )

    input_observation = adapter.make_observation(
        identity=identity,
        stage=Stage.INPUT,
        user_input=request.user_input,
        context_items=[],
        tool_candidate=None,
    )
    prepared = adapter.prepare_tool_call(request, identity)

    assert input_observation.run_id == prepared.observation.run_id
    assert input_observation.trace_id == prepared.observation.trace_id
    assert input_observation.session_id == prepared.observation.session_id
    assert prepared.observation.scenario_id == request.scenario_id
    assert prepared.observation.stage == Stage.TOOL
    assert prepared.observation.tool_candidate == (prepared.candidate.model_dump())
    assert prepared.observation.created_at.utcoffset() is not None


def test_each_tool_candidate_has_a_new_id():
    adapter = RuntimeAdapter()
    request = make_request()
    identity = adapter.create_identity(None, request.scenario_id)

    first = adapter.prepare_tool_call(request, identity)
    second = adapter.prepare_tool_call(request, identity)

    assert first.candidate.tool_call_id != second.candidate.tool_call_id
    assert first.observation.run_id == second.observation.run_id


def test_observation_is_independent_of_input_mutation():
    adapter = RuntimeAdapter()
    request = make_request()
    identity = adapter.create_identity(None, request.scenario_id)

    prepared = adapter.prepare_tool_call(request, identity)

    request.context_items[0]["content"] = "변경된 문서"
    request.tool_request.tool_arguments["path"] = "changed.txt"
    prepared.candidate.tool_arguments["path"] = "also-changed.txt"

    assert prepared.observation.context_items[0]["content"] == "정상 문서"
    assert prepared.observation.tool_candidate["tool_arguments"] == {
        "path": "documents/meeting.txt",
    }


def test_tool_stage_requires_candidate():
    adapter = RuntimeAdapter()
    identity = adapter.create_identity(None, None)

    with pytest.raises(ValueError, match="ToolCandidate"):
        adapter.make_observation(
            identity=identity,
            stage=Stage.TOOL,
            user_input="테스트",
            context_items=[],
            tool_candidate=None,
        )


def test_prepare_rejects_different_scenario():
    adapter = RuntimeAdapter()
    request = make_request()
    identity = adapter.create_identity(None, "OTHER-SCENARIO")

    with pytest.raises(ValueError, match="scenario_id"):
        adapter.prepare_tool_call(request, identity)
