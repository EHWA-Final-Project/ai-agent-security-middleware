"""Inputs for the reusable Agent-MCP execution path."""

from dataclasses import dataclass, field
from pathlib import PurePosixPath


@dataclass(frozen=True)
class AgentCaseInput:
    scenario_id: str
    user_input: str
    documents: dict[str, str] = field(default_factory=dict)
    tool_descriptions: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.scenario_id.strip():
            raise ValueError("scenario_id must not be empty")

        if not self.user_input.strip():
            raise ValueError("user_input must not be empty")

        for path, content in self.documents.items():
            parsed = PurePosixPath(path)

            if (
                parsed.is_absolute()
                or ".." in parsed.parts
                or len(parsed.parts) < 2
                or parsed.parts[0] != "docs"
                or "\\" in path
            ):
                raise ValueError("Document must be inside docs/")

            if not isinstance(content, str):
                raise TypeError("Document content must be a string")

        for name, description in self.tool_descriptions.items():
            if name not in {"demo/read_file", "demo/send_email"}:
                raise ValueError("Unsupported tool description target")

            if not isinstance(description, str):
                raise TypeError("Tool description must be a string")

        object.__setattr__(self, "documents", dict(self.documents))
        object.__setattr__(
            self, "tool_descriptions", dict(self.tool_descriptions)
        )
