"""Sprint 1 synthetic specifications only; no runner, model or metric results."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SURFACES = {
    "MCP-D01": "tool_metadata",
    "PI-T01": "tool_response",
    "PI-I01": "resource_content",
    "TL-U01": "tool_request",
    "TL-A01": "tool_request",
    "TL-X01": "resource_content",
}


class _Spec(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ToolCallSpec(_Spec):
    server_name: Literal["fixture-mcp"]
    tool_name: Literal["read_file", "send_email"]
    arguments: dict


class ScenarioSpec(_Spec):
    scenario_id: str = Field(pattern=r"^mcp-s1:[a-z0-9-]+:(attack|benign)$")
    sample_id: str = Field(pattern=r"^mcp-s1:sample:[a-z0-9-]+:(attack|benign)$")
    pair_id: str = Field(min_length=1)
    attack_id: Literal["MCP-D01", "PI-T01", "PI-I01", "TL-U01", "TL-A01", "TL-X01"]
    classification: Literal["attack", "benign"]
    entry_surface: Literal["tool_metadata", "tool_response", "resource_content", "tool_request"]
    legitimate_task: str = Field(min_length=1)
    lower_trust_payload: str = Field(min_length=1)
    legitimate_tool_call: ToolCallSpec
    intended_tool_call: ToolCallSpec
    expected_good_behavior: str = Field(min_length=1)
    expected_bad_behavior: str | None
    conditions_to_observe: list[str] = Field(min_length=1)
    semantic_oracle: str = Field(min_length=1)
    policy_fixture: Literal["read_only", "bounded_tools"]

    @model_validator(mode="after")
    def check_semantics(self) -> ScenarioSpec:
        if self.entry_surface != SURFACES[self.attack_id]:
            raise ValueError("entry surface disagrees with attack family")
        for identifier in (self.scenario_id, self.sample_id):
            if not identifier.endswith(":" + self.classification):
                raise ValueError("ID suffix must match classification")
        if self.classification == "attack":
            if not self.expected_bad_behavior or not self.expected_bad_behavior.strip():
                raise ValueError("attack requires expected_bad_behavior")
        elif self.expected_bad_behavior is not None:
            raise ValueError("benign expected_bad_behavior must be null")
        for value in (
            self.pair_id, self.legitimate_task, self.lower_trust_payload,
            self.expected_good_behavior, self.semantic_oracle, *self.conditions_to_observe,
        ):
            if not value.strip():
                raise ValueError("text fields must not be blank")
        return self


class ScenarioManifest(_Spec):
    schema_version: Literal["mcp-sprint1-v1"]
    source_type: Literal["synthetic"]
    execution_scope: Literal["specification_only"]
    safety: Literal["In-memory simulated tools only; no network, filesystem access or real sending."]
    scenarios: list[ScenarioSpec] = Field(min_length=1)

    @model_validator(mode="after")
    def check_pairs(self) -> ScenarioManifest:
        for field in ("scenario_id", "sample_id"):
            ids = [getattr(row, field) for row in self.scenarios]
            if len(ids) != len(set(ids)):
                raise ValueError(f"duplicate {field}")
        pairs: dict[str, list[ScenarioSpec]] = {}
        for row in self.scenarios:
            pairs.setdefault(row.pair_id, []).append(row)
        for rows in pairs.values():
            if len(rows) != 2 or {r.classification for r in rows} != {"attack", "benign"}:
                raise ValueError("each pair requires one attack and one benign record")
            for field in (
                "attack_id", "entry_surface", "legitimate_task", "legitimate_tool_call", "policy_fixture",
            ):
                if getattr(rows[0], field) != getattr(rows[1], field):
                    raise ValueError(f"paired {field} must match")
        if {row.attack_id for row in self.scenarios} != set(SURFACES):
            raise ValueError("Sprint 1 requires all six attack families")
        return self


def load_mcp_scenarios(path: str | Path) -> ScenarioManifest:
    """Validate an independent manifest; never convert to legacy P0 scenarios."""
    return ScenarioManifest.model_validate(json.loads(Path(path).read_text(encoding="utf-8")))


@dataclass(frozen=True)
class BoundaryObservation:
    """Local boundary facts, scoped to ONE candidate call, not the whole run.

    Unknown stays None. This deliberately has no attack/task/defense-success
    property: those require independent semantic or causal evidence.
    """

    pre_tool_block: bool | None = None
    tool_executed: bool | None = None
    call_count: int | None = None
    post_tool_output_block: bool | None = None
    output_allowed: bool | None = None

    def __post_init__(self) -> None:
        for name in ("pre_tool_block", "tool_executed", "post_tool_output_block", "output_allowed"):
            value = getattr(self, name)
            if value is not None and type(value) is not bool:
                raise ValueError(f"{name} must be bool or null")
        if self.call_count is not None and (type(self.call_count) is not int or self.call_count < 0):
            raise ValueError("call_count must be a nonnegative integer or null")
        if self.pre_tool_block is True and (
            self.tool_executed is True or (self.call_count is not None and self.call_count > 0)
            or self.post_tool_output_block is True
        ):
            raise ValueError("pre-tool block contradicts later activity for the same candidate")
        if self.post_tool_output_block is True and (
            self.output_allowed is True or self.tool_executed is False
        ):
            raise ValueError("post-tool block contradicts execution/delivery facts")
        if self.tool_executed is True and self.call_count == 0:
            raise ValueError("MCP tool execution requires a server call")

    @property
    def boundary_classification(self) -> str:
        if self.pre_tool_block is True and self.tool_executed is False and self.call_count == 0:
            return "pre_tool_block"
        if (self.post_tool_output_block is True and self.tool_executed is True
                and self.output_allowed is False):
            return "post_tool_output_block"
        if self.tool_executed is True:
            return "tool_executed"
        return "unknown"
