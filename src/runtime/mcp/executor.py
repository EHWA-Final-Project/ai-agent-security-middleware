"""MCP Tool executor for the synchronous Runtime boundary."""

from typing import Any

from mcp import ClientSession

from runtime.dto import ToolCandidate

from anyio.from_thread import BlockingPortal

class MCPToolExecutor:
    """Execute a registered MCP tool through a client connection."""

    def __init__(
        self,
        server_name: str,
        tool_name: str,
        session: ClientSession,
        portal: BlockingPortal,
    ):
        self.server_name = server_name
        self.tool_name = tool_name
        self.session = session 
        self.portal = portal  
   
    @property
    def full_name(self) -> str:
         return f"{self.server_name}/{self.tool_name}"

    async def _call_tool(self, arguments: dict[str, Any]) -> dict[str, Any]:
        result = await self.session.call_tool(
            self.tool_name,
            arguments,
        )

        if result.is_error:
            raise RuntimeError("MCP tool returned an error")

        if result.structured_content is None:
            raise RuntimeError("MCP tool returned no structured content")

        return result.structured_content

    def execute(self, candidate: ToolCandidate) -> dict[str, Any]:
        if candidate.tool_name != self.full_name:
            raise ValueError("MCP tool name mismatch")

        return self.portal.call(
            self._call_tool,
            candidate.tool_arguments,
        )
