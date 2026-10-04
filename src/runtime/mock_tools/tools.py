"""외부 파일 접근이나 네트워크 전송이 없는 Mock Tool."""

from copy import deepcopy
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from runtime.dto import ToolCandidate


class ReadFileArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    path: str = Field(min_length=1)


class SendEmailArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    to: list[str] = Field(min_length=1)
    subject: str
    body: str


class MockReadFile:
    name = "read_file"

    def __init__(self, documents: dict[str, str]) -> None:
        self._documents = dict(documents)
        self.call_count = 0

    def execute(self, candidate: ToolCandidate) -> dict[str, Any]:
        self.call_count += 1

        if candidate.tool_name != self.name:
            raise ValueError("Tool 이름이 read_file과 일치하지 않습니다.")

        arguments = ReadFileArguments.model_validate(candidate.tool_arguments)

        if arguments.path not in self._documents:
            raise FileNotFoundError(f"Mock 문서를 찾을 수 없습니다: {arguments.path}")

        return {
            "path": arguments.path,
            "content": self._documents[arguments.path],
        }


class MockSendEmail:
    name = "send_email"

    def __init__(self) -> None:
        self.call_count = 0
        self._outbox: list[dict[str, Any]] = []

    @property
    def outbox(self) -> list[dict[str, Any]]:
        return deepcopy(self._outbox)

    def execute(self, candidate: ToolCandidate) -> dict[str, Any]:
        self.call_count += 1

        if candidate.tool_name != self.name:
            raise ValueError("Tool 이름이 send_email과 일치하지 않습니다.")

        arguments = SendEmailArguments.model_validate(candidate.tool_arguments)

        if any(not recipient.strip() for recipient in arguments.to):
            raise ValueError("수신자는 빈 문자열일 수 없습니다.")

        message_id = f"mock-message-{len(self._outbox) + 1:04d}"

        self._outbox.append(
            {
                "message_id": message_id,
                "tool_call_id": candidate.tool_call_id,
                "to": list(arguments.to),
                "subject": arguments.subject,
                "body": arguments.body,
            }
        )

        return {
            "message_id": message_id,
            "accepted": True,
            "delivery": "mock",
        }
