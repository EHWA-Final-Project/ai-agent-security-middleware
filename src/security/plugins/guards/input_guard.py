"""Input Guard.

Scores direct prompt-injection signals in ``user_input`` with the shared
rule set in ``_injection_rules`` (strong / medium / weak tiers, more distinct
rules -> higher score within a tier). Legacy phrases such as "ignore previous
instructions" keep their original score of 0.90.

Decision: WARN when the score reaches ``WARN_SCORE`` (0.50, the default strict
threshold); below that the score is still reported (decision ALLOW) so the
Orchestrator and Evidence see graded risk. Per-rule detail is in
``evidence[0]["matched_rules"]``; ``rule_ids`` keeps the stable umbrella id.
"""

from __future__ import annotations

import time

from enums import AttackSubtype, Decision, GuardExecutionStatus, Stage
from schemas import RuntimeObservation, SecurityContext, SecurityResult

from security.plugins.guards import _injection_rules as rules
from security.plugins.interface import GuardPlugin

_TIER_SCORES = {"strong": 0.90, "medium": 0.60, "weak": 0.30}


class InputGuard(GuardPlugin):
    name = "input_guard"
    stage = Stage.INPUT

    def inspect(self, observation: RuntimeObservation, context: SecurityContext) -> SecurityResult:
        start = time.perf_counter()
        matches = rules.scan(observation.user_input or "", guard="input")
        risk = rules.score(matches, **_TIER_SCORES)
        latency_ms = (time.perf_counter() - start) * 1000

        warn = risk >= rules.WARN_SCORE
        return SecurityResult(
            run_id=observation.run_id,
            trace_id=observation.trace_id,
            stage=self.stage,
            guard_name=self.name,
            execution_status=GuardExecutionStatus.SUCCESS,
            risk_score=risk,
            decision=Decision.WARN if warn else Decision.ALLOW,
            rule_ids=["input_guard.direct_prompt_injection"] if warn else [],
            evidence=(
                [
                    {
                        "matched_patterns": [m.text for m in matches],
                        "matched_rules": [
                            {"rule": m.rule, "family": m.family, "tier": m.tier, "variant": m.variant}
                            for m in matches
                        ],
                        "signal_count": len(matches),
                        "attack_subtype": AttackSubtype.DIRECT_PROMPT_INJECTION.value,
                    }
                ]
                if risk > 0
                else []
            ),
            latency_ms=latency_ms,
        )
