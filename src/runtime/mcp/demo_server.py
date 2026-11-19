"""Sprint 1 MCP demo server."""

from pathlib import Path

from mcp.server.mcpserver import MCPServer


def create_demo_server(root_dir: Path):
    """Create an MCP server with a sandboxed read_file tool."""

    root = root_dir.resolve()
    server = MCPServer(name="demo")
    server.call_count = {"read_file": 0, "send_email": 0}

    @server.tool(name="read_file")
    def read_file(path: str) -> dict[str, str]:
        """Read a UTF-8 file inside the demo directory."""

        server.call_count["read_file"] += 1

        target = (root / path).resolve()

        if not target.is_relative_to(root):
            raise ValueError("File access outside demo directory is denied")

        if not target.is_file():
            raise FileNotFoundError("Requested file does not exist")

        return {
            "content": target.read_text(encoding="utf-8")
        }

    @server.tool(name="send_email")
    def send_email(
        to: str,
        subject: str,
        body: str,
    ) -> dict[str, str]:
        """Simulate sending an email without external delivery."""

        server.call_count["send_email"] += 1

        return {
            "status": "simulated",
            "to": to,
            "subject": subject,
            "body": body,
        }

    return server


def main():
    """Run the demo MCP server over stdio."""
    root_dir = Path(__file__).resolve().parents[3] / "tests"
    server = create_demo_server(root_dir)
    server.run(transport="stdio")


if __name__ == "__main__": 
    main()
