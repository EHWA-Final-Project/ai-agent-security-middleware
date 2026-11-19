"""Real stdio MCP cross-PR checks; no model effectiveness claims."""

import os
import sys

import anyio
import pytest
from anyio.from_thread import start_blocking_portal
from enums import Decision, RunStatus
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from evidence.collector import EvidenceCollector
from evidence.sqlite_repository import SQLiteEvidenceRepository
from runtime.adapter import RuntimeAdapter
from runtime.dto import RuntimeRequest, ToolRequest
from runtime.mcp.host_adapter import discover_tools
from security.plugins.guards.tool_guard import ToolPolicy
from security.policy.conditions import load_condition, make_condition_security_factory


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
    (docs / "clean.txt").write_text("hello", encoding="utf-8")
    (docs / "secret.txt").write_text("API_KEY=sk-fake-sprint1", encoding="utf-8")
    params = StdioServerParameters(
        command=sys.executable,
        args=["-c", ("import sys; from pathlib import Path; "
              "from runtime.mcp.demo_server import create_demo_server; "
              "create_demo_server(Path(sys.argv[1])).run(transport='stdio')"), str(tmp_path)],
        env={**os.environ, "PYTHONPATH": os.pathsep.join(
            [os.path.abspath("src"), os.path.abspath("shared")])},
    )
    policy = ToolPolicy(
        allowed_tools=frozenset({"demo/read_file", "demo/send_email"}),
        allowed_path_prefixes=("docs",),
        allowed_recipient_domains=frozenset({"corp.com"}),
    )
    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        counting = CountingSession(session)
        tools = await discover_tools("demo", counting, portal)
        tools.update(await discover_tools("evil", counting, portal))
        repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")
        collector = EvidenceCollector(repository)
        cases = [
            ("clean", "demo/read_file", {"path": "docs/clean.txt"}, policy, 1),
            ("other-server", "evil/read_file", {"path": "docs/clean.txt"}, policy, 0),
            ("missing-policy", "demo/read_file", {"path": "docs/clean.txt"}, None, 0),
            ("outside", "demo/read_file", {"path": "private.txt"}, policy, 0),
            ("traversal", "demo/read_file", {"path": "docs/../private.txt"}, policy, 0),
            ("email", "demo/send_email", {"to": "a@corp.com", "subject": "s", "body": "b"}, policy, 1),
            ("bad-domain", "demo/send_email", {"to": "a@evil.invalid", "subject": "s", "body": "b"}, policy, 0),
            ("secret", "demo/read_file", {"path": "docs/secret.txt"}, policy, 1),
        ]
        for label, name, arguments, tool_policy, expected_calls in cases:
            before = len(counting.calls)
            request = RuntimeRequest(
                user_input="Process the document.", context_items=[],
                session_id="sprint1-qa", scenario_id=label,
                tool_request=ToolRequest(tool_name=name, tool_arguments=arguments),
            )

            def run(request=request, tool_policy=tool_policy):
                return RuntimeAdapter().run(
                    request, tools=tools, evidence=collector,
                    security_factory=make_condition_security_factory(
                        load_condition(condition), collector, tool_policy=tool_policy),
                )

            result = await anyio.to_thread.run_sync(run)
            assert result.run_status == RunStatus.COMPLETED, (label, result.errors)
            assert not result.errors
            assert len(counting.calls) - before == expected_calls, label
            assert result.execution.executed is bool(expected_calls), label
            if not expected_calls:
                assert result.decision.decision == Decision.BLOCK, label
                assert result.output_allowed is False
                assert result.forward_output is None
            elif label == "secret":
                assert "sk-fake-sprint1" in result.execution.output["content"]
                # Agreed B/C policy: execute once, then withhold the secret output.
                assert result.decision.decision == Decision.BLOCK
                assert result.output_allowed is False
                assert result.forward_output is None
                assert result.decision.sanitized_output is None
                assert "sk-fake-sprint1" not in str(result.forward_output)
                assert "output_guard.secret_leakage" in result.decision.triggered_rules
                assert result.decision.cumulative_risk_score == pytest.approx(0.95)
            else:
                assert result.decision.decision == Decision.ALLOW
                assert result.output_allowed is True
            events = repository.list_events_by_run(result.identity.run_id)
            assert all(e.run_id == result.identity.run_id and
                       e.trace_id == result.identity.trace_id for e in events)
            decisions = [e for e in events if e.event_type == "SECURITY_DECISION"]
            executions = [e for e in events if e.event_type == "EXECUTION_RESULT"]
            assert len(decisions) == len(executions) == 1
            assert decisions[0].payload["decision"] == result.decision.decision.value
            assert executions[0].payload["executed"] == result.execution.executed
            assert executions[0].payload["tool_call_id"] == result.execution.tool_call_id
            assert executions[0].payload["execution_state"] == result.execution.execution_state.value
            assert decisions[0].payload["policy_version"] == result.decision.policy_version
            if label == "secret":
                # Output delivery protection does not redact persisted raw evidence.
                assert "sk-fake-sprint1" in executions[0].payload["output"]["content"]
                output_results = [e for e in events if e.event_type == "SECURITY_RESULT"
                                  and e.payload.get("guard_name") == "output_guard"]
                assert len(output_results) == 1
                assert output_results[0].payload["risk_score"] == pytest.approx(0.95)
                assert "output_guard.secret_leakage" in output_results[0].payload["rule_ids"]
            print(f"{condition}/{label}: tools/call={expected_calls}, "
                  f"executed={result.execution.executed}, output_allowed={result.output_allowed}")


@pytest.mark.parametrize("condition", ["B", "C"])
def test_real_mcp_cross_boundary(tmp_path, condition):
    with start_blocking_portal() as portal:
        portal.call(exercise, portal, tmp_path, condition)
