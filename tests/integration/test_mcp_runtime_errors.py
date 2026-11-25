"""Real MCP argument and runtime failure integration tests."""

import os
import sys

import anyio
import pytest
from anyio.from_thread import start_blocking_portal
from enums import ExecutionState, RunStatus
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from evidence.collector import EvidenceCollector
from evidence.sqlite_repository import SQLiteEvidenceRepository
from runtime.adapter import RuntimeAdapter
from runtime.dto import RuntimeRequest, ToolRequest
from runtime.mcp.host_adapter import discover_tools
from security.plugins.guards.tool_guard import ToolPolicy
from security.policy.conditions import (
    load_condition,
    make_condition_security_factory,
)

POLICY = ToolPolicy(
    allowed_tools=frozenset({
        "demo/read_file",
        "demo/send_email",
    }),
    allowed_recipient_domains=frozenset({"corp.com"}),
    allowed_path_prefixes=("docs",),
)


class CountingSession:
    def __init__(self, session):
        self.session = session
        self.calls = []
        self.results = []

    async def list_tools(self):
        return await self.session.list_tools()

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        result = await self.session.call_tool(name, arguments)
        self.results.append(result)
        return result


CASES = [
    (
        "valid-email",
        "demo/send_email",
        {"to": "a@corp.com", "subject": "s", "body": "b"},
        False,
    ),
    (
        "list-recipient",
        "demo/send_email",
        {"to": ["a@corp.com"], "subject": "s", "body": "b"},
        True,
    ),
    (
        "extra-argument",
        "demo/send_email",
        {
            "to": "a@corp.com",
            "subject": "s",
            "body": "b",
            "reply_to": "test@example.invalid",
        },
        False,
    ),
    (
        "missing-subject",
        "demo/send_email",
        {"to": "a@corp.com", "body": "b"},
        True,
    ),
    (
        "missing-file",
        "demo/read_file",
        {"path": "docs/not_found.txt"},
        True,
    ),
]


async def exercise(portal, tmp_path, condition, case):
    label, tool_name, arguments, expected_error = case

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "runtime.mcp.demo_server"],
        env={
            **os.environ,
            "PYTHONPATH": os.pathsep.join([
                os.path.abspath("src"),
                os.path.abspath("shared"),
            ]),
        },
    )

    async with (
        stdio_client(params) as (read, write),
        ClientSession(
            read, write, read_timeout_seconds=10.0
        ) as session,
    ):
        await session.initialize()

        counting = CountingSession(session)
        tools = await discover_tools(
            "demo", counting, portal
        )

        repository = SQLiteEvidenceRepository(
            tmp_path / "evidence.db"
        )
        collector = EvidenceCollector(repository)

        request = RuntimeRequest(
            user_input="Process the document.",
            context_items=[],
            session_id="mcp-runtime-errors",
            scenario_id=label,
            tool_request=ToolRequest(
                tool_name=tool_name,
                tool_arguments=arguments,
            ),
        )

        def run():
            return RuntimeAdapter().run(
                request,
                tools=tools,
                evidence=collector,
                security_factory=make_condition_security_factory(
                    load_condition(condition),
                    collector,
                    tool_policy=POLICY,
                ),
            )

        result = await anyio.to_thread.run_sync(run)

        assert len(counting.calls) == 1
        assert result.execution is not None
        assert result.execution.executed is True
        assert len(counting.results) == 1

        server_error = counting.results[0].is_error

        if expected_error is not None:
            assert server_error == expected_error

        if server_error:
            assert result.run_status == RunStatus.FAILED
            assert (
                result.execution.execution_state
                == ExecutionState.FAILED
            )
            assert result.execution.error is not None
            assert result.execution.error.code == "TOOL_EXECUTION_ERROR"
            assert result.output_allowed is False
            assert result.forward_output is None
            assert result.errors
        else:
            assert result.run_status == RunStatus.COMPLETED
            assert (
                result.execution.execution_state
                == ExecutionState.EXECUTED
            )
            assert result.output_allowed is True
            assert result.forward_output is not None

            if label == "extra-argument":
                assert "reply_to" not in result.forward_output

        events = repository.list_events_by_run(
            result.identity.run_id
        )

        assert all(
            event.run_id == result.identity.run_id
            and event.trace_id == result.identity.trace_id
            for event in events
        )

        executions = [
            event for event in events
            if event.event_type == "EXECUTION_RESULT"
        ]

        assert len(executions) == 1
        payload = executions[0].payload

        assert payload["executed"] is True
        assert (
            payload["execution_state"]
            == result.execution.execution_state.value
        )
        assert (
            payload["tool_call_id"]
            == result.execution.tool_call_id
        )

        if server_error:
            assert payload["error"]["code"] == "TOOL_EXECUTION_ERROR"
            assert payload["output"] is None

        print(
            f"\n{condition}/{label}: "
            f"sdk_calls={len(counting.calls)}, "
            f"server_error={server_error}, "
            f"executed={result.execution.executed}, "
            f"state={result.execution.execution_state.value}, "
            f"status={result.run_status.value}, "
            f"output_allowed={result.output_allowed}, "
            f"events={len(events)}"
        )


@pytest.mark.parametrize("condition", ["B", "C"])
@pytest.mark.parametrize(
    "case", CASES, ids=[case[0] for case in CASES]
)
def test_real_mcp_runtime_arguments(
    tmp_path, condition, case
):
    with start_blocking_portal() as portal:
        portal.call(
            exercise, portal, tmp_path, condition, case
        )
