"""MCP Host Adapter for registering namespaced tools."""

from anyio.from_thread import BlockingPortal
from mcp import ClientSession

from runtime.mcp.executor import MCPToolExecutor


async def discover_tools(
    server_name: str,
    session: ClientSession,
    portal: BlockingPortal,
) -> dict[str, MCPToolExecutor]:
    """Discover MCP tools and register them with namespaced names."""

    result = await session.list_tools()
    tools = {}

    for tool in result.tools:
        executor = MCPToolExecutor(
            server_name=server_name,
            tool_name=tool.name,
            session=session,
            portal=portal,
        )

        if executor.full_name in tools:
            raise ValueError(
                f"Duplicate MCP tool: {executor.full_name}"
            )

        tools[executor.full_name] = executor

    return tools
