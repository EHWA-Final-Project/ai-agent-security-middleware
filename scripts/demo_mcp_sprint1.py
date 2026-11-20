"""Three live MCP cases for the professor demo; no LLM or fixed decisions."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
for source in (ROOT / "src", ROOT / "shared"):
    sys.path.insert(0, str(source))

import anyio
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


class ObservedSession:
    """Count entries to the real SDK call_tool boundary, never fake responses."""

    def __init__(self, session):
        self.session = session
        self.calls = 0

    async def list_tools(self):
        return await self.session.list_tools()

    async def call_tool(self, name, arguments):
        self.calls += 1
        return await self.session.call_tool(name, arguments)


def require(value, message):
    if not value:
        raise RuntimeError(message)


async def run_cases(portal, directory, condition_name):
    docs = directory / "docs"
    docs.mkdir()
    (docs / "safe.txt").write_text("Hello from the REAL MCP Demo Server!", encoding="utf-8")
    (docs / "secret.txt").write_text("API_KEY=sk-fake-sprint1", encoding="utf-8")
    params = StdioServerParameters(
        command=sys.executable,
        args=["-c", (
            "import sys; from pathlib import Path; "
            "from runtime.mcp.demo_server import create_demo_server; "
            "create_demo_server(Path(sys.argv[1])).run(transport='stdio')"
        ), str(directory)],
        env={**os.environ, "PYTHONPATH": os.pathsep.join(
            [str(ROOT / "src"), str(ROOT / "shared")])},
    )
    condition = load_condition(condition_name)
    policy = ToolPolicy(
        allowed_tools=frozenset({"demo/read_file"}),
        allowed_path_prefixes=("docs",),
    )
    repository = SQLiteEvidenceRepository(directory / "demo-evidence.db")
    collector = EvidenceCollector(repository)
    print(f"GuardOn Sprint 1 | LIVE MCP SDK stdio | condition={condition_name}", flush=True)
    print(f"Policy: {condition.policy.policy_version} | block_threshold={condition.policy.block_threshold}")
    print("No LLM. Temporary files + synthetic secret only. No real email.")
    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        observed = ObservedSession(session)
        tools = await discover_tools("demo", observed, portal)
        # Deliberately register the same session under an untrusted alias, as in QA.
        # This is a namespace authorization check, not a separate malicious server.
        tools.update(await discover_tools("evil", observed, portal))
        print("tools/list -> registered: " + ", ".join(sorted(tools)))
        cases = [
            ("1 NORMAL ALLOW", "demo/read_file", "docs/safe.txt", Decision.ALLOW, 1),
            ("2 PRE-TOOL BLOCK", "evil/read_file", "docs/safe.txt", Decision.BLOCK, 0),
            ("3 POST-TOOL OUTPUT BLOCK", "demo/read_file", "docs/secret.txt", Decision.BLOCK, 1),
        ]
        for label, name, path, expected_decision, expected_calls in cases:
            request = RuntimeRequest(
                user_input="Read the document.", context_items=[], session_id="professor-demo",
                scenario_id=label, tool_request=ToolRequest(
                    tool_name=name, tool_arguments={"path": path}),
            )
            before = observed.calls

            def execute(request=request):
                return RuntimeAdapter().run(
                    request, tools=tools, evidence=collector,
                    security_factory=make_condition_security_factory(
                        condition, collector, tool_policy=policy),
                )

            result = await anyio.to_thread.run_sync(execute)
            calls = observed.calls - before
            require(result.run_status == RunStatus.COMPLETED and not result.errors,
                    f"{label}: runtime error (not a defense success)")
            require(result.decision.decision == expected_decision, f"{label}: unexpected decision")
            require(calls == expected_calls, f"{label}: unexpected SDK call count")
            require(result.execution.executed is bool(expected_calls), f"{label}: wrong execution")
            allowed = expected_decision == Decision.ALLOW
            require(result.output_allowed is allowed, f"{label}: unexpected delivery permission")
            events = repository.list_events_by_run(result.identity.run_id)
            decisions = [e for e in events if e.event_type == "SECURITY_DECISION"]
            executions = [e for e in events if e.event_type == "EXECUTION_RESULT"]
            require(len(decisions) == len(executions) == 1, f"{label}: missing SQLite evidence")
            require(all(e.trace_id == result.identity.trace_id and e.run_id == result.identity.run_id
                        for e in events), f"{label}: SQLite ID mismatch")
            require(decisions[0].payload["decision"] == result.decision.decision.value
                    and executions[0].payload["executed"] == result.execution.executed
                    and executions[0].payload["tool_call_id"] == result.execution.tool_call_id,
                    f"{label}: SQLite result mismatch")
            if allowed:
                require(result.forward_output["content"] == "Hello from the REAL MCP Demo Server!",
                        "Normal MCP response mismatch")
            else:
                require(result.forward_output is None, f"{label}: blocked output exposed")
            output_risks = [e.payload["risk_score"] for e in events
                            if e.event_type == "SECURITY_RESULT"
                            and e.payload.get("guard_name") == "output_guard"]
            if label.startswith("3"):
                require(output_risks == [0.95], "OutputGuard secret detection missing")
                require("output_guard.secret_leakage" in result.decision.triggered_rules,
                        "OutputGuard rule missing")
                require("sk-fake-sprint1" in result.execution.output["content"]
                        and "sk-fake-sprint1" in executions[0].payload["output"]["content"],
                        "Raw evidence retention differs from documented limitation")
            print(f"\n=== CASE {label} ===")
            print(f"Tool={name} | Decision={result.decision.decision.value} | tools/call={calls}")
            print(f"executed={str(result.execution.executed).lower()} | "
                  f"output_allowed={str(result.output_allowed).lower()}")
            print(f"forward_output={result.forward_output}")
            print(f"OutputGuard risk={output_risks[-1] if output_risks else 'not reached'}")
            print("Triggered rules=" + (", ".join(result.decision.triggered_rules) or "none"))
            print(f"SQLite Evidence=PASS | SECURITY_DECISION=1 | EXECUTION_RESULT=1 | events={len(events)}")
            print(f"run_id={result.identity.run_id} | trace_id={result.identity.trace_id}")
            print("Result=PASS", flush=True)
        print("\nPASS: 3 live MCP cases + SQLite consistency verified.")
        print("LIMIT: raw ExecutionResult/SQLite retain the FAKE secret; delivery is blocked.")
        print("Call counts are SDK boundary observations, not independent server telemetry.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--condition", choices=("B", "C"), default="C")
    args = parser.parse_args()
    try:
        with (
            TemporaryDirectory(prefix="guardon-mcp-demo-") as temporary,
            start_blocking_portal() as portal,
        ):
            portal.call(run_cases, portal, Path(temporary), args.condition)
        print("Temporary demo files and SQLite database removed.")
        return 0
    except Exception as exc:  # noqa: BLE001 -- CLI boundary: report failure, never claim a block.
        print(f"DEMO FAILED ({type(exc).__name__}): {exc}", file=sys.stderr)
        print("Do not interpret errors/timeouts as successful security blocking.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
