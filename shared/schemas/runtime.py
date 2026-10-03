"""Owner: 지원. Stubs kept minimal so imports succeed team-wide; 지원 owns
the real implementation/behavior of these.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from enums import ExecutionState, Stage
from errors import ErrorDetail
from pydantic import BaseModel, Field


class RuntimeObservation(BaseModel):
    run_id: str
    session_id: str
    trace_id: str
    scenario_id: str | None = None
    stage: Stage
    user_input: str
    context_items: list[Any] = Field(default_factory=list)
    tool_candidate: dict[str, Any] | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ExecutionResult(BaseModel):
    run_id: str
    trace_id: str
    tool_call_id: str | None = None
    tool_name: str | None = None
    execution_state: ExecutionState
    executed: bool
    output: Any | None = None
    error: ErrorDetail | None = None
    latency_ms: float
