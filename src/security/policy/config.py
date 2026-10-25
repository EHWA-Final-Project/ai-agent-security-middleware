"""Policy Config.

P0 baseline: strict_threshold=0.50, block_threshold=0.80 are initial smoke
values, not final tuned thresholds. Any change to thresholds/weights MUST
bump policy_version to preserve experiment reproducibility.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class CoordinationMode(str, Enum):
    """How Guards relate to each other within one evaluate() call.

    LINKED: cross-layer. Risk accumulates across Guards (noisy-OR) and an
        earlier WARN raises the inspection mode for later stages.
    INDEPENDENT: each Guard is judged on its own score against the
        thresholds. No accumulation, no mode escalation, no sanitize
        retry. Same Guards and thresholds, no propagation.

    Kept in the policy module rather than shared/enums since it is Security
    Core's own configuration, not a cross-part contract.
    """

    LINKED = "linked"
    INDEPENDENT = "independent"


class PolicyConfig(BaseModel):
    policy_version: str
    strict_threshold: float = 0.50
    block_threshold: float = 0.80
    guard_weights: dict[str, float] = Field(default_factory=dict)
    critical_rule_ids: list[str] = Field(default_factory=list)
    #: Changing this changes behavior, so per the freeze rule a different
    #: mode should always ship with its own policy_version.
    coordination_mode: CoordinationMode = CoordinationMode.LINKED

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
