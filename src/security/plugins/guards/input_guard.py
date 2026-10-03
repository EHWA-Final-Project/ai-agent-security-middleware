"""Input Guard · P0 baseline.

Minimal rule: flags direct prompt-injection-style phrases in user_input.
This is intentionally a simple keyword/pattern check for Sprint 1 — it
exists to prove the plugin/registry/orchestrator wiring works end to end,
not to be the final detection logic.
"""

from __future__ import annotations

import time

from enums import AttackSubtype, Decision, GuardExecutionStatus, Stage
from schemas import RuntimeObservation, SecurityContext, SecurityResult

from security.plugins.interface import GuardPlugin

_SUSPICIOUS_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "reveal your system prompt",
    "disregard the above",
]


class InputGuard(GuardPlugin):
    name = "input_guard"
    stage = Stage.INPUT

    def inspect(self, observation: RuntimeObservation, context: SecurityContext) -> SecurityResult:
        start = time.perf_counter()
        text = (observation.user_input or "").lower()

        matched = [p for p in _SUSPICIOUS_PATTERNS if p in text]
        latency_ms = (time.perf_counter() - start) * 1000

        if matched:
            return SecurityResult(
                run_id=observation.run_id,
                trace_id=observation.trace_id,
                stage=self.stage,
                guard_name=self.name,
                execution_status=GuardExecutionStatus.SUCCESS,
                risk_score=0.9,
                decision=Decision.WARN,
                rule_ids=["input_guard.direct_prompt_injection"],
                evidence=[
                    {
                        "matched_patterns": matched,
                        "attack_subtype": AttackSubtype.DIRECT_PROMPT_INJECTION.value,
                    }
                ],
                latency_ms=latency_ms,
            )

        return SecurityResult(
            run_id=observation.run_id,
            trace_id=observation.trace_id,
            stage=self.stage,
            guard_name=self.name,
            execution_status=GuardExecutionStatus.SUCCESS,
            risk_score=0.0,
            decision=Decision.ALLOW,
            rule_ids=[],
            evidence=[],
            latency_ms=latency_ms,
        )
