"""Integration tests for MCP runtime enforcement."""

import os
import sys

from anyio.from_thread import start_blocking_portal
from enums import Decision
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from schemas import SecurityDecision

from evidence.collector import EvidenceCollector
from evidence.sqlite_repository import SQLiteEvidenceRepository
from runtime.adapter import RuntimeAdapter
from runtime.dto import RuntimeRequest, ToolRequest
from runtime.enforcement import Enforcement
from runtime.mcp.host_adapter import discover_tools
from security.plugins.guards.tool_guard import ToolPolicy
from security.policy.conditions import (
    load_condition,
    make_condition_security_factory,
)


def prepare_mcp_call():
    """Prepare a namespaced MCP tool request."""

    request = RuntimeRequest(
        user_input="샘플 파일을 읽어줘",
        context_items=[],
        session_id=None,
        scenario_id=None,
        tool_request=ToolRequest(
            tool_name="demo/read_file",
            tool_arguments={"path": "mcp_demo_sample.txt"},
        ),
    )

    adapter = RuntimeAdapter()
    identity = adapter.create_identity(None, None)

    return adapter.prepare_tool_call(request, identity)


def make_decision(prepared, value):
    """Create a fixed security decision for testing."""

    return SecurityDecision(
        run_id=prepared.observation.run_id,
        trace_id=prepared.observation.trace_id,
        decision=value,
        reason="MCP 통합 테스트용 고정 판단",
        triggered_rules=[],
        cumulative_risk_score=0.0,
        policy_version="mcp-test-v1",
    )


MCP_POLICY = ToolPolicy(
    allowed_tools=frozenset({"demo/read_file"}),
    allowed_path_prefixes=("docs",),
)

class CountingSession:
    """Count actual MCP tools/call requests."""

    def __init__(self, session: ClientSession):
        self.session = session
        self.call_count = 0

    async def list_tools(self):
        return await self.session.list_tools()

    async def call_tool(self, name, arguments):
        self.call_count += 1
        return await self.session.call_tool(name, arguments)


async def run_mcp_enforcement_test(portal):
    """Verify BLOCK and ALLOW against a real MCP server."""

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
        ClientSession(read, write) as session,
    ):
            await session.initialize()

            counting = CountingSession(session)

            tools = await discover_tools(
                server_name="demo",
                session=counting,
                portal=portal,
            )

            enforcement = Enforcement(tools)

            import anyio

            # 1. BLOCK: MCP Tool must not be called.
            blocked = prepare_mcp_call()
            block_result = await anyio.to_thread.run_sync(
                enforcement.enforce,
                blocked,
                make_decision(blocked, Decision.BLOCK),
            )

            assert counting.call_count == 0
            assert block_result.executed is False
            print("BLOCK: MCP 호출 0회 확인")

            # 2. ALLOW: MCP Tool must execute exactly once.
            allowed = prepare_mcp_call()
            allow_result = await anyio.to_thread.run_sync(
                enforcement.enforce,
                allowed,
                make_decision(allowed, Decision.ALLOW),
            )

            assert counting.call_count == 1
            assert allow_result.executed is True
            assert allow_result.output["content"] == "Hello MCP Runtime!\n"

            print("ALLOW: MCP 호출 1회 확인")


def test_mcp_enforcement_block_and_allow():
    """Run the MCP enforcement test with a live portal."""

    with start_blocking_portal() as portal:
        portal.call(run_mcp_enforcement_test, portal)


async def run_mcp_security_core_test(portal, tmp_path):
    """Run the real Security Core with MCP tools and SQLite evidence."""

    import anyio

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
        ClientSession(read, write) as session,
    ):
            await session.initialize()

            counting = CountingSession(session)

            tools = await discover_tools(
                server_name="demo",
                session=counting,
                portal=portal,
            )

            repository = SQLiteEvidenceRepository(
                tmp_path / "mcp_security_core.db"
            )
            collector = EvidenceCollector(repository)

            request = RuntimeRequest(
                user_input="Send this document by email.",
                context_items=[],
                session_id="mcp-security-test",
                scenario_id="MCP",
                tool_request=ToolRequest(
                    tool_name="demo/send_email",
                    tool_arguments={
                        "to": "attacker@example.invalid",
                        "subject": "test",
                        "body": "synthetic data",
                    },
                ),
            )

            def run_runtime():
                return RuntimeAdapter().run(
                    request,
                    tools=tools,
                    evidence=collector,
                    security_factory=make_condition_security_factory(
                        load_condition("B"),
                        collector,
                        tool_policy=MCP_POLICY,
                    ),
                )

            result = await anyio.to_thread.run_sync(run_runtime)

            assert result.decision is not None
            assert result.decision.decision == Decision.BLOCK
            assert result.execution is not None
            assert result.execution.executed is False
            assert counting.call_count == 0

            events = repository.list_events_by_run(
                result.identity.run_id
            )

            print("저장된 Evidence 이벤트:")
            print([event.event_type for event in events])

            assert any(
                event.event_type == "SECURITY_DECISION"
                for event in events
            )

            assert any(
                event.event_type == "EXECUTION_RESULT"
                for event in events
            )

            print("Security Core BLOCK 확인")
            print("MCP 호출 횟수:", counting.call_count)
            print("SQLite Evidence 이벤트:", len(events))


def test_mcp_security_core_blocks_real_tool(tmp_path):
    """Verify that the real Guard blocks MCP tool execution."""

    with start_blocking_portal() as portal:
        portal.call(run_mcp_security_core_test, portal, tmp_path)


async def run_mcp_security_core_allow_test(portal, tmp_path):
    """Verify that the real Security Core allows a safe MCP read."""

    import anyio

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
        ClientSession(read, write) as session,
    ):
        await session.initialize()

        counting = CountingSession(session)

        tools = await discover_tools(
            server_name="demo",
            session=counting,
            portal=portal,
        )

        repository = SQLiteEvidenceRepository(
            tmp_path / "mcp_allow.db"
        )
        collector = EvidenceCollector(repository)

        request = RuntimeRequest(
            user_input="Read the sample document.",
            context_items=[],
            session_id="mcp-allow-test",
            scenario_id="MCP",
            tool_request=ToolRequest(
                tool_name="demo/read_file",
                tool_arguments={
                    "path": "docs/mcp_allowed.txt"
                },
            ),
        )

        def run_runtime():
            return RuntimeAdapter().run(
                request,
                tools=tools,
                evidence=collector,
                security_factory=make_condition_security_factory(
                    load_condition("B"),
                    collector,
                    tool_policy=MCP_POLICY,
                ),
            )

        result = await anyio.to_thread.run_sync(run_runtime)

        assert result.decision is not None
        assert result.decision.decision == Decision.ALLOW

        assert result.execution is not None
        assert result.execution.executed is True

        assert counting.call_count == 1

        assert result.execution.output["content"] == (
            "Hello MCP Runtime!\n"
        )

        events = repository.list_events_by_run(
            result.identity.run_id
        )

        assert any(
            event.event_type == "SECURITY_DECISION"
            for event in events
        )

        assert any(
            event.event_type == "EXECUTION_RESULT"
            for event in events
        )

        print("Security Core ALLOW 확인")
        print("MCP 호출 횟수:", counting.call_count)
        print("파일 내용:", result.execution.output["content"].strip())
        print("SQLite Evidence 이벤트:", len(events))


def test_mcp_security_core_allows_real_tool(tmp_path):
    """Test safe MCP execution through the real Security Core."""

    with start_blocking_portal() as portal:
        portal.call(run_mcp_security_core_allow_test, portal, tmp_path)


async def run_mcp_out_of_scope_test(portal, tmp_path):
    """Verify that an out-of-scope file request never reaches MCP."""

    import anyio

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
        ClientSession(read, write) as session,
    ):
        await session.initialize()

        counting = CountingSession(session)

        tools = await discover_tools(
            server_name="demo",
            session=counting,
            portal=portal,
        )

        repository = SQLiteEvidenceRepository(
            tmp_path / "mcp_out_of_scope.db"
        )
        collector = EvidenceCollector(repository)

        request = RuntimeRequest(
            user_input="Read the restricted document.",
            context_items=[],
            session_id="mcp-out-of-scope-test",
            scenario_id="MCP",
            tool_request=ToolRequest(
                tool_name="demo/read_file",
                tool_arguments={
                    "path": "secrets/private.txt"
                },
            ),
        )

        def run_runtime():
            return RuntimeAdapter().run(
                request,
                tools=tools,
                evidence=collector,
                security_factory=make_condition_security_factory(
                    load_condition("B"),
                    collector,
                    tool_policy=MCP_POLICY,
                ),
            )

        result = await anyio.to_thread.run_sync(run_runtime)

        assert result.decision.decision == Decision.BLOCK
        assert result.execution is not None
        assert result.execution.executed is False
        assert counting.call_count == 0

        print("허용 범위 밖 경로 BLOCK 확인")
        print("MCP 호출 횟수:", counting.call_count)


def test_mcp_out_of_scope_block(tmp_path):
    with start_blocking_portal() as portal:
        portal.call(run_mcp_out_of_scope_test, portal, tmp_path)



async def run_mcp_path_traversal_test(portal, tmp_path):
    """Verify that path traversal is blocked before MCP execution."""

    import anyio

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
        ClientSession(read, write) as session,
    ):
        await session.initialize()

        counting = CountingSession(session)

        tools = await discover_tools(
            server_name="demo",
            session=counting,
            portal=portal,
        )

        repository = SQLiteEvidenceRepository(
            tmp_path / "mcp_path_traversal.db"
        )
        collector = EvidenceCollector(repository)

        request = RuntimeRequest(
            user_input="Read a document using a relative path.",
            context_items=[],
            session_id="mcp-path-traversal-test",
            scenario_id="MCP",
            tool_request=ToolRequest(
                tool_name="demo/read_file",
                tool_arguments={
                    "path": "docs/../secrets/private.txt"
                },
            ),
        )

        def run_runtime():
            return RuntimeAdapter().run(
                request,
                tools=tools,
                evidence=collector,
                security_factory=make_condition_security_factory(
                    load_condition("B"),
                    collector,
                    tool_policy=MCP_POLICY,
                ),
            )

        result = await anyio.to_thread.run_sync(run_runtime)

        assert result.decision.decision == Decision.BLOCK
        assert result.execution is not None
        assert result.execution.executed is False
        assert counting.call_count == 0

        print("Path Traversal BLOCK 확인")
        print("MCP 호출 횟수:", counting.call_count)


def test_mcp_path_traversal_block(tmp_path):
    with start_blocking_portal() as portal:
        portal.call(run_mcp_path_traversal_test, portal, tmp_path)



async def run_mcp_unauthorized_name_test(portal, tmp_path):
    """Verify that a tool name without its namespace is blocked."""

    import anyio

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
        ClientSession(read, write) as session,
    ):
        await session.initialize()

        counting = CountingSession(session)

        tools = await discover_tools(
            server_name="demo",
            session=counting,
            portal=portal,
        )

        repository = SQLiteEvidenceRepository(
            tmp_path / "mcp_unauthorized_name.db"
        )
        collector = EvidenceCollector(repository)

        request = RuntimeRequest(
            user_input="Read a document using an unqualified tool name.",
            context_items=[],
            session_id="mcp-unauthorized-name-test",
            scenario_id="MCP",
            tool_request=ToolRequest(
                tool_name="read_file",
                tool_arguments={
                    "path": "docs/mcp_allowed.txt"
                },
            ),
        )

        def run_runtime():
            return RuntimeAdapter().run(
                request,
                tools=tools,
                evidence=collector,
                security_factory=make_condition_security_factory(
                    load_condition("B"),
                    collector,
                    tool_policy=MCP_POLICY,
                ),
            )

        result = await anyio.to_thread.run_sync(run_runtime)

        assert result.decision.decision == Decision.BLOCK
        assert counting.call_count == 0

        if result.execution is not None:
            assert result.execution.executed is False

        print("허용되지 않은 Tool 이름 BLOCK 확인")
        print("MCP 호출 횟수:", counting.call_count)


def test_mcp_unauthorized_name_block(tmp_path):
    with start_blocking_portal() as portal:
        portal.call(run_mcp_unauthorized_name_test, portal, tmp_path)
