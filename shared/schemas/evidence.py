"""Owner: Wana. Stubs kept minimal so imports succeed team-wide; Wana owns
the real implementation/behavior of these.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from enums import AttackSubtype, ScenarioType, Stage
from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    event_id: str
    run_id: str
    trace_id: str
    scenario_id: str | None = None
    event_type: str
    stage: Stage | None = None
    payload: Any
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class EvaluationResult(BaseModel):
    scenario_id: str
    run_id: str
    scenario_type: ScenarioType
    attack_subtype: AttackSubtype | None = None
    expected_result: Any
    actual_result: Any
    attack_success: bool | None = None
    task_success: bool | None = None
    false_positive: bool | None = None
