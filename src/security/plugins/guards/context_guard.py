"""Context Guard · P0 baseline.

Checks observation.context_items — documents/context the agent reads —
for instructions hidden in that content trying to redirect the agent
(indirect prompt injection).
"""

from __future__ import annotations

import time

from enums import AttackSubtype, Decision, GuardExecutionStatus, Stage
from schemas import RuntimeObservation, SecurityContext, SecurityResult

from security.plugins.interface import GuardPlugin

_SUSPICIOUS_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard the above",
    "disregard previous instructions",
    "new instructions:",
    "system:",
    "reveal your system prompt",
]


class ContextGuard(GuardPlugin):
    name = "context_guard"
    stage = Stage.CONTEXT

    def inspect(self, observation: RuntimeObservation, context: SecurityContext) -> SecurityResult:
        start = time.perf_counter()

        if not observation.context_items:
            latency_ms = (time.perf_counter() - start) * 1000
            return SecurityResult(
                run_id=observation.run_id,
                trace_id=observation.trace_id,
                stage=self.stage,
                guard_name=self.name,
                execution_status=GuardExecutionStatus.SUCCESS,
                risk_score=0.0,
                decision=Decision.ALLOW,
                latency_ms=latency_ms,
            )

        combined_text = " ".join(str(item) for item in observation.context_items).lower()
        matched = [p for p in _SUSPICIOUS_PATTERNS if p in combined_text]
        latency_ms = (time.perf_counter() - start) * 1000

        if matched:
            return SecurityResult(
                run_id=observation.run_id,
                trace_id=observation.trace_id,
                stage=self.stage,
                guard_name=self.name,
                execution_status=GuardExecutionStatus.SUCCESS,
                risk_score=0.88,
                decision=Decision.WARN,
                rule_ids=["context_guard.indirect_prompt_injection"],
                evidence=[
                    {
                        "matched_patterns": matched,
                        "attack_subtype": AttackSubtype.INDIRECT_PROMPT_INJECTION.value,
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
            latency_ms=latency_ms,
        )
