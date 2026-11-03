"""Context Guard.

Scores instructions hidden in ``observation.context_items`` (documents and
retrieved content the agent reads, i.e. indirect prompt injection) with the
shared rule set in ``_injection_rules``. Legacy phrases keep their original
score of 0.88. On top of the Input rules, imperative tool / exfiltration
directives ("send ... to x@y.com") count here, because untrusted content has
no business issuing them.

Decision: WARN when the score reaches ``WARN_SCORE`` (0.50); below that the
score is still reported (decision ALLOW). Per-rule detail is in
``evidence[0]["matched_rules"]``; ``rule_ids`` keeps the stable umbrella id.
"""

from __future__ import annotations

import time
from typing import Any

from enums import AttackSubtype, Decision, GuardExecutionStatus, Stage
from schemas import RuntimeObservation, SecurityContext, SecurityResult

from security.plugins.guards import _injection_rules as rules
from security.plugins.interface import GuardPlugin

_TIER_SCORES = {"strong": 0.88, "medium": 0.62, "weak": 0.30}


def _item_text(item: Any) -> str:
    if isinstance(item, dict) and isinstance(item.get("content"), str):
        return item["content"]
    return str(item)


class ContextGuard(GuardPlugin):
    name = "context_guard"
    stage = Stage.CONTEXT

    def inspect(self, observation: RuntimeObservation, context: SecurityContext) -> SecurityResult:
        start = time.perf_counter()

        combined_text = "\n".join(_item_text(i) for i in (observation.context_items or []))
        matches = rules.scan(combined_text, guard="context") if combined_text else []
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
            rule_ids=["context_guard.indirect_prompt_injection"] if warn else [],
            evidence=(
                [
                    {
                        "matched_patterns": [m.text for m in matches],
                        "matched_rules": [
                            {"rule": m.rule, "family": m.family, "tier": m.tier, "variant": m.variant}
                            for m in matches
                        ],
                        "signal_count": len(matches),
                        "attack_subtype": AttackSubtype.INDIRECT_PROMPT_INJECTION.value,
                    }
                ]
                if risk > 0
                else []
            ),
            latency_ms=latency_ms,
        )
