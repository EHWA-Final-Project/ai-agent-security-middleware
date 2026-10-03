"""Owner: Fatin. Security Core schemas — SecurityResult, SecurityContext,
SecurityDecision.
"""

from __future__ import annotations

from typing import Any

from enums import Decision, GuardExecutionStatus, InspectionMode, Stage
from errors import ErrorDetail
from pydantic import BaseModel, Field

from schemas.runtime import ExecutionResult


class SecurityResult(BaseModel):

    run_id: str
    trace_id: str
    stage: Stage
    guard_name: str
    execution_status: GuardExecutionStatus
    risk_score: float | None = None
    decision: Decision | None = None
    rule_ids: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    latency_ms: float
    error: ErrorDetail | None = None


class SecurityContext(BaseModel):
    run_id: str
    trace_id: str
    current_stage: Stage
    cumulative_risk_score: float = 0.0
    inspection_mode: InspectionMode = InspectionMode.STANDARD
    previous_results: list[SecurityResult] = Field(default_factory=list)
    policy_version: str
    execution_result: ExecutionResult | None = None
    pending_sanitized_output: str | None = None


class SecurityDecision(BaseModel):
    run_id: str
    trace_id: str
    decision: Decision
    reason: str
    triggered_rules: list[str] = Field(default_factory=list)
    cumulative_risk_score: float
    policy_version: str
    sanitized_output: str | None = None
