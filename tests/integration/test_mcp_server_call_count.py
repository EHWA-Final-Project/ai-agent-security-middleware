"""Verify actual MCP server-side tool invocation counts."""

import json
import os
import sys

import anyio
import pytest
from anyio.from_thread import start_blocking_portal
from enums import Decision, ExecutionState, RunStatus
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
import json
import sys
from pathlib import Path

from runtime.mcp.demo_server import create_demo_server


class PersistentCounter(dict):
    def __init__(self, initial, path):
        super().__init__(initial)
        self.path = path
        self.save()

    def save(self):
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self), encoding="utf-8")
        temporary.replace(self.path)

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self.save()


root = Path(sys.argv[1])
counter_path = Path(sys.argv[2])

server = create_demo_server(root)
server.call_count = PersistentCounter(
    server.call_count, counter_path
)
server.run(transport="stdio")
"""


class CountingSession:
    def __init__(self, session):
        self.session = session
        self.calls = []

    async def list_tools(self):
        return await self.session.list_tools()

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return await self.session.call_tool(name, arguments)


async def exercise(portal, tmp_path, condition):
    docs = tmp_path / "docs"
    docs.mkdir()

    (docs / "safe.txt").write_text(
        "Safe sample document.",
        encoding="utf-8",
    )

    counter_path = tmp_path / "server_counts.json"

    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-c",
            SERVER_CODE,
            str(tmp_path),
            str(counter_path),
        ],
        env={
            **os.environ,
            "PYTHONPATH": os.pathsep.join([
                os.path.abspath("src"),
                os.path.abspath("shared"),
            ]),
        },
    )

    policy = ToolPolicy(
        allowed_tools=frozenset({"demo/read_file"}),
        allowed_path_prefixes=("docs",),
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

        def server_counts():
            return json.loads(
                counter_path.read_text(encoding="utf-8")
            )

        assert server_counts() == {
            "read_file": 0,
            "send_email": 0,
        }

        cases = [
            (
                "normal",
                "demo/read_file",
                {"path": "docs/safe.txt"},
                True,
            ),
            (
                "unauthorized-email",
                "demo/send_email",
                {
                    "to": "test@example.invalid",
                    "subject": "test",
                    "body": "synthetic data",
                },
                False,
            ),
            (
                "blocked-path",
                "demo/read_file",
                {"path": "private.txt"},
                False,
            ),
        ]

        for label, name, arguments, allowed in cases:
            before_server = server_counts()
            before_sdk = len(counting.calls)

            request = RuntimeRequest(
                user_input="Process the document.",
                context_items=[],
                session_id="mcp-server-counter",
                scenario_id=label,
                tool_request=ToolRequest(
                    tool_name=name,
                    tool_arguments=arguments,
                ),
            )

            def run(request=request):
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

            after_server = server_counts()

            server_delta = {
                key: after_server[key] - before_server[key]
                for key in before_server
            }

            sdk_delta = len(counting.calls) - before_sdk

            assert result.run_status == RunStatus.COMPLETED
            assert result.execution is not None
            assert not result.errors

            assert sdk_delta == int(allowed)
            assert sum(server_delta.values()) == int(allowed)
            assert result.execution.executed is allowed
            assert result.output_allowed is allowed

            if allowed:
                assert result.decision.decision == Decision.ALLOW
                assert (
                    result.execution.execution_state
                    == ExecutionState.EXECUTED
                )
                assert server_delta["read_file"] == 1
                assert result.forward_output["content"] == (
                    "Safe sample document."
                )
            else:
                assert result.decision.decision == Decision.BLOCK
                assert (
                    result.execution.execution_state
                    == ExecutionState.BLOCKED
                )
                assert result.forward_output is None
                assert server_delta == {
                    "read_file": 0,
                    "send_email": 0,
                }

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
            assert executions[0].payload["executed"] is allowed
            assert (
                executions[0].payload["tool_call_id"]
                == result.execution.tool_call_id
            )

            print(
                f"\n{condition}/{label}: "
                f"sdk_calls={sdk_delta}, "
                f"server_calls={server_delta}, "
                f"executed={result.execution.executed}, "
                f"output_allowed={result.output_allowed}, "
                f"events={len(events)}"
            )

        assert server_counts() == {
            "read_file": 1,
            "send_email": 0,
        }


@pytest.mark.parametrize("condition", ["B", "C"])
def test_actual_mcp_server_call_count(tmp_path, condition):
    with start_blocking_portal() as portal:
        portal.call(
            exercise, portal, tmp_path, condition
        )
