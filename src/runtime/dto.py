"""지원 Runtime 내부 DTO 초안. 연결 파트 검토 후 확정한다."""

from typing import Any

from pydantic import BaseModel, ConfigDict
from schemas import RuntimeObservation


class RuntimeDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ToolRequest(RuntimeDTO):
    tool_name: str
    tool_arguments: dict[str, Any]


class RuntimeRequest(RuntimeDTO):
    user_input: str
    context_items: list[Any]
    session_id: str | None
    scenario_id: str | None
    tool_request: ToolRequest | None


class RunIdentity(RuntimeDTO):
    run_id: str
    session_id: str
    trace_id: str
    scenario_id: str | None


class ToolCandidate(RuntimeDTO):
    tool_call_id: str
    tool_name: str
    tool_arguments: dict[str, Any]


class PreparedToolCall(RuntimeDTO):
    """내부 보관용 묶음. 팀 공통 Schema에 추가하는 필드가 아니다."""

    observation: RuntimeObservation
    candidate: ToolCandidate
