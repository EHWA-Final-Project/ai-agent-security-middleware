"""Mock/Fixture helpers for Contract Tests.

RuntimeObservation is owned by 지원 — this factory produces a valid mock
instance so other parts can be tested against the agreed schema shape
before 지원's real Runtime Adapter exists.
"""

from __future__ import annotations

from enums import Stage
from ids import new_run_id, new_session_id, new_trace_id
from schemas.runtime import RuntimeObservation


def mock_runtime_observation(
    *,
    user_input: str = "Summarize this document for me.",
    run_id: str | None = None,
    trace_id: str | None = None,
    stage: Stage = Stage.INPUT,
    tool_candidate: dict | None = None,
) -> RuntimeObservation:
    return RuntimeObservation(
        run_id=run_id or new_run_id(),
        session_id=new_session_id(),
        trace_id=trace_id or new_trace_id(),
        stage=stage,
        user_input=user_input,
        tool_candidate=tool_candidate,
    )
