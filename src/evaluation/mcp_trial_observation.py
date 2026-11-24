"""Evaluation-local sidecars; no shared Runtime/Evidence DTO changes."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from schemas.security import SecurityDecision, SecurityResult

from .mcp_scenarios import BoundaryObservation

Identifier = Annotated[str, Field(min_length=1, pattern=r"\S")]
Count = Annotated[int, Field(ge=0)]
Scope = Literal["mapping_only", "fixture_execution", "actual_llm_mcp"]
Decision = Literal["ALLOW", "WARN", "BLOCK"]


class ObservationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


class UnknownObservation(ObservationModel):
    unknown_reasons: dict[str, Identifier] = Field(default_factory=dict)

    @model_validator(mode="after")
    def explain_unknowns(self):
        for name in type(self).model_fields:
            if getattr(self, name) is None:
                self.unknown_reasons.setdefault(name, "not_observed")
            else:
                self.unknown_reasons.pop(name, None)
        return self


class ToolAction(ObservationModel):
    server_name: Identifier
    tool_name: Identifier
    arguments: dict[str, Any]


class SDKCall(UnknownObservation):
    """Client invocation, distinct from server receipt and tool body execution."""

    method: Literal["tools/list", "tools/call", "resources/read"]
    timestamp: datetime
    candidate_id: Identifier | None = None
    mcp_call_id: Identifier | None = None
    evidence_ref: Identifier | None = None


class CandidateObservation(UnknownObservation):
    candidate_id: Identifier
    timestamp: datetime
    mcp_call_id: Identifier | None = None
    parent_mcp_call_id: Identifier | None = None
    server_name: Identifier | None = None
    tool_name: Identifier | None = None
    candidate_source: Literal["model", "fixture"] | None = None
    model_selected_tool: ToolAction | None = None
    requested_tool: ToolAction | None = None
    security_decision: SecurityDecision | None = None
    guard_decision: Decision | None = None
    guard_results: list[SecurityResult] | None = None
    tool_policy_decision: Decision | None = None
    prevention_sources: list[Literal["guard", "tool_policy", "host", "server"]] | None = None
    pre_tool_block: bool | None = None
    warn: bool | None = None
    call_count: Count | None = None
    tool_executed: bool | None = None
    output_allowed: bool | None = None
    output_delivered: bool | None = None
    output_destination: Literal["model", "user"] | None = None
    post_tool_output_block: bool | None = None
    evidence_refs: list[Identifier] | None = None

    @model_validator(mode="after")
    def validate_boundaries(self):
        BoundaryObservation(**{
            key: getattr(self, key) for key in (
                "pre_tool_block", "tool_executed", "call_count",
                "post_tool_output_block", "output_allowed",
            )
        })
        if self.output_delivered is True and (
            self.output_allowed is False or self.post_tool_output_block is True
        ):
            raise ValueError("delivery contradicts output withholding")
        if self.model_selected_tool is not None and self.candidate_source != "model":
            raise ValueError("model selection requires model candidate source")
        for action in (self.model_selected_tool, self.requested_tool):
            if action is not None and (
                action.server_name != self.server_name or action.tool_name != self.tool_name
            ):
                raise ValueError("action target differs from candidate target")
        return self


class BackendObservation(UnknownObservation):
    """Incrementally populated by a backend, preserving facts on timeout/error."""

    run_status: Literal["completed", "timeout", "error", "incomplete"] | None = None
    model_tool_selection_observed: bool | None = None
    candidates: list[CandidateObservation] = Field(default_factory=list)
    sdk_calls: list[SDKCall] | None = None
    output_delivered: bool | None = None
    output_destination: Literal["model", "user"] | None = None
    model_disposition: Literal["followed", "ignored", "rejected"] | None = None
    model_response_refs: list[Identifier] | None = None
    attack_objective_achieved: bool | None = None
    legitimate_task_success: bool | None = None
    judge_version: Identifier | None = None
    outcome_evidence_refs: list[Identifier] | None = None
    evidence_refs: list[Identifier] | None = None
    error_stage: Identifier | None = None
    error_detail: Identifier | None = None
    timed_out: bool | None = None


class TrialSidecar(UnknownObservation):
    schema_version: Literal["external-mcp-trial-v1"] = "external-mcp-trial-v1"
    run_id: Identifier
    trace_id: Identifier
    scenario_id: Identifier
    sample_id: Identifier
    pair_id: Identifier
    classification: Literal["attack", "benign"]
    condition: Literal["A", "B", "C", "D"]
    repeat: Count
    seed: int | None
    model: dict[str, Any] | None
    policy_version: Identifier
    policy_enabled: bool | None
    output_injection_scan: bool
    execution_scope: Scope
    backend_id: Identifier | None
    manifest_sha256: Identifier
    mapped_case_sha256: Identifier
    code_revision: Identifier
    provenance: dict[str, Any]
    started_at: datetime
    latency_ms: Annotated[float, Field(ge=0)] | None
    latency_scope: str = "backend execution including cancellation cleanup"
    timeout_seconds: Annotated[float, Field(gt=0)]
    evidence_validated: bool | None
    evidence_issues: list[str] = Field(default_factory=list)
    observation: BackendObservation
