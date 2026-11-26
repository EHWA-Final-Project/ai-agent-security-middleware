import asyncio
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock

import pytest
from agent_mcp_observation import AgentRunObservation, public_summary
from run_agent_mcp_e2e import ObservedSession


def make_session():
    observation = AgentRunObservation(
        scenario_id="sdk-observation-test",
        condition="D",
    )
    session = AsyncMock()
    observed = ObservedSession(session, observation)
    return observation, session, observed


def test_discovery_invocations_are_recorded_separately():
    observation, session, observed = make_session()

    asyncio.run(observed.list_tools())
    asyncio.run(observed.list_tools())

    assert session.list_tools.await_count == 2
    assert observed.calls == 0
    assert len(observation.sdk_calls) == 2

    for call in observation.sdk_calls:
        assert call["method"] == "tools/list"
        assert call["candidate_id"] is None
        assert call["tool_name"] is None
        assert call["invoked"] is True
        assert call["mcp_call_id"] is None


def test_tool_invocation_links_candidate():
    observation, session, observed = make_session()
    observed.active_candidate_id = "candidate-1"

    asyncio.run(observed.call_tool("read_file", {"path": "docs/a.txt"}))

    session.call_tool.assert_awaited_once_with(
        "read_file", {"path": "docs/a.txt"}
    )
    assert observed.calls == 1

    call = observation.sdk_calls[0]

    assert call["method"] == "tools/call"
    assert call["candidate_id"] == "candidate-1"
    assert call["tool_name"] == "demo/read_file"
    assert call["invoked"] is True
    assert call["mcp_call_id"] is None


def test_sequential_invocations_keep_candidate_identity():
    observation, _, observed = make_session()

    observed.active_candidate_id = "candidate-1"
    asyncio.run(observed.call_tool("read_file", {"path": "docs/a.txt"}))

    observed.active_candidate_id = "candidate-2"
    asyncio.run(observed.call_tool("read_file", {"path": "docs/b.txt"}))

    observed.active_candidate_id = None
    asyncio.run(observed.list_tools())

    assert observed.calls == 2

    assert [
        call["candidate_id"] for call in observation.sdk_calls
    ] == ["candidate-1", "candidate-2", None]


def test_failed_sdk_invocation_is_preserved():
    observation, session, observed = make_session()
    observed.active_candidate_id = "candidate-1"
    session.call_tool.side_effect = RuntimeError("private error")

    with pytest.raises(RuntimeError):
        asyncio.run(observed.call_tool("read_file", {}))

    assert observed.calls == 1
    assert len(observation.sdk_calls) == 1
    assert observation.sdk_calls[0]["invoked"] is True
    assert observation.sdk_calls[0]["candidate_id"] == "candidate-1"


def test_failed_discovery_invocation_is_preserved():
    observation, session, observed = make_session()
    session.list_tools.side_effect = TimeoutError()

    with pytest.raises(TimeoutError):
        asyncio.run(observed.list_tools())

    assert observed.calls == 0
    assert len(observation.sdk_calls) == 1
    assert observation.sdk_calls[0]["method"] == "tools/list"


def test_no_sdk_entry_creates_no_tool_invocation():
    observation, session, observed = make_session()

    asyncio.run(observed.list_tools())
    observed.active_candidate_id = "candidate-1"
    observed.active_candidate_id = None

    assert observed.calls == 0
    session.call_tool.assert_not_awaited()
    assert all(
        call["method"] != "tools/call"
        for call in observation.sdk_calls
    )


def test_sdk_timestamp_is_utc():
    observation, _, observed = make_session()

    asyncio.run(observed.list_tools())

    timestamp = datetime.fromisoformat(
        observation.sdk_calls[0]["timestamp"]
    )

    assert timestamp.utcoffset() == timedelta(0)


def test_public_summary_excludes_raw_sdk_arguments():
    observation, _, observed = make_session()
    observed.active_candidate_id = "candidate-1"

    asyncio.run(observed.call_tool(
        "read_file",
        {"path": "private-secret-value"},
    ))

    summary = public_summary(observation)

    assert summary["sdk_calls"] == observation.sdk_calls
    assert "private-secret-value" not in json.dumps(summary)

    assert set(summary["sdk_calls"][0]) == {
        "method",
        "timestamp",
        "candidate_id",
        "tool_name",
        "invoked",
        "mcp_call_id",
    }
