"""Real MCP transport timeout and disconnect checks."""

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

SERVER_CODE = """
import os
import sys
import anyio
from mcp.server.mcpserver import MCPServer

server = MCPServer(name="demo")
mode = sys.argv[1]

@server.tool(name="read_file")
async def read_file(path: str) -> dict[str, str]:
    if mode == "disconnect":
        os._exit(1)
    await anyio.sleep(5)
    return {"content": "delayed response"}

server.run(transport="stdio")
"""


class CountingSession:
    def __init__(self, session):
        self.session = session
        self.calls = 0

    async def list_tools(self):
        return await self.session.list_tools()

    async def call_tool(self, name, arguments):
        self.calls += 1
        return await self.session.call_tool(name, arguments)


async def exercise(portal, tmp_path, condition, mode):
    params = StdioServerParameters(
        command=sys.executable,
        args=["-c", SERVER_CODE, mode],
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

        tools["demo/read_file"].timeout_seconds = (
            0.5 if mode == "timeout" else 3.0
        )

        repository = SQLiteEvidenceRepository(
            tmp_path / "evidence.db"
        )
        collector = EvidenceCollector(repository)

        policy = ToolPolicy(
            allowed_tools=frozenset({"demo/read_file"}),
            allowed_path_prefixes=("docs",),
        )

        request = RuntimeRequest(
            user_input="Read the document.",
            context_items=[],
            session_id="mcp-transport-failure",
            scenario_id=mode,
            tool_request=ToolRequest(
                tool_name="demo/read_file",
                tool_arguments={"path": "docs/test.txt"},
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
                    tool_policy=policy,
                ),
            )

        result = await anyio.to_thread.run_sync(run)

        assert counting.calls == 1
        assert result.run_status == RunStatus.FAILED
        assert result.execution is not None
        assert result.execution.executed is True
        assert (
            result.execution.execution_state
            == ExecutionState.FAILED
        )
        assert result.execution.error is not None
        assert result.execution.error.code == "TOOL_EXECUTION_ERROR"
        assert result.output_allowed is False
        assert result.forward_output is None
        assert result.errors

        details = result.execution.error.details or {}
        exception_type = details.get("exception_type")

        if mode == "timeout":
            assert exception_type == "TimeoutError"

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

        assert payload["execution_state"] == "FAILED"
        assert payload["output"] is None
        assert payload["error"]["code"] == "TOOL_EXECUTION_ERROR"
        assert (
            payload["tool_call_id"]
            == result.execution.tool_call_id
        )

        print(
            f"\n{condition}/{mode}: "
            f"sdk_calls={counting.calls}, "
            f"exception={exception_type}, "
            f"status={result.run_status.value}, "
            f"output_allowed={result.output_allowed}, "
            f"events={len(events)}"
        )


@pytest.mark.parametrize("condition", ["B", "C"])
@pytest.mark.parametrize("mode", ["timeout", "disconnect"])
def test_mcp_transport_failure(tmp_path, condition, mode):
    with start_blocking_portal() as portal:
        portal.call(
            exercise, portal, tmp_path, condition, mode
        )
