"""Policy Config."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

import yaml
from enums import InspectionMode
from pydantic import BaseModel, Field


class CoordinationMode(str, Enum):

    LINKED = "linked"
    INDEPENDENT = "independent"


class PolicyConfig(BaseModel):
    policy_version: str
    strict_threshold: float = 0.50
    block_threshold: float = 0.80
    guard_weights: dict[str, float] = Field(default_factory=dict)
    critical_rule_ids: list[str] = Field(default_factory=list)
    coordination_mode: CoordinationMode = CoordinationMode.LINKED
    #: Inspection mode a run starts in. STANDARD (A/B/C) keeps today's behavior;
    #: FAST (condition D) starts with the cheaper Context scan and escalates to
    #: STANDARD as soon as any Guard reports risk.
    initial_inspection_mode: InspectionMode = InspectionMode.STANDARD
    #: Output Guard also scans executed tool output for injected instructions
    #: (PI-T01). Off by default so existing A/B/C results stay reproducible.
    output_injection_scan: bool = False

    def weight_for(self, guard_name: str) -> float:
        """P0: all guard weights default to 1.0 unless overridden in config."""
        return self.guard_weights.get(guard_name, 1.0)

    def is_critical_rule(self, rule_id: str) -> bool:
        return rule_id in self.critical_rule_ids


def load_policy_config(path: str | Path) -> PolicyConfig:
    path = Path(path)
    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return PolicyConfig(**raw)
