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

Condition D (inspection mode FAST): the scan is gated, i.e. a rule is skipped
only when none of its trigger words is in the text, so the matches equal those
of the ungated scan. If anything in the FAST path fails, the whole text is
scanned in full. In STANDARD and STRICT mode this guard behaves as before.
"""

from __future__ import annotations

import time
from typing import Any

from enums import AttackSubtype, Decision, GuardExecutionStatus, InspectionMode, Stage
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

    def __init__(self, *, extended_rules: bool = False) -> None:
        self._extended = extended_rules

    def inspect(self, observation: RuntimeObservation, context: SecurityContext) -> SecurityResult:
        start = time.perf_counter()

        items = observation.context_items or []
        depth: str | None = None
        if context.inspection_mode == InspectionMode.FAST and items:
            try:
                matches, depth = self._scan_fast(items), "gated"
            except Exception:  # noqa: BLE001 — adaptive path must never weaken inspection
                matches, depth = self._scan_full(items), None
        else:
            matches = self._scan_full(items)
        risk = rules.score(matches, **_TIER_SCORES)
        latency_ms = (time.perf_counter() - start) * 1000

        warn = risk >= rules.WARN_SCORE
        evidence: list[dict[str, Any]] = []
        if risk > 0:
            evidence.append(
                {
                    "matched_patterns": [m.text for m in matches],
                    "matched_rules": [
                        {"rule": m.rule, "family": m.family, "tier": m.tier, "variant": m.variant}
                        for m in matches
                    ],
                    "signal_count": len(matches),
                    "attack_subtype": AttackSubtype.INDIRECT_PROMPT_INJECTION.value,
                }
            )
        if depth is not None:
            # Only present in FAST mode (condition D).
            if evidence:
                evidence[0]["inspection_depth"] = depth
            else:
                evidence.append({"inspection_depth": depth})
        return SecurityResult(
            run_id=observation.run_id,
            trace_id=observation.trace_id,
            stage=self.stage,
            guard_name=self.name,
            execution_status=GuardExecutionStatus.SUCCESS,
            risk_score=risk,
            decision=Decision.WARN if warn else Decision.ALLOW,
            rule_ids=["context_guard.indirect_prompt_injection"] if warn else [],
            evidence=evidence,
            latency_ms=latency_ms,
        )

    def _scan_full(self, items: list[Any]) -> list[rules.Match]:
        combined_text = "\n".join(_item_text(i) for i in items)
        return rules.scan(combined_text, guard="context", extended=self._extended) if combined_text else []

    def _scan_fast(self, items: list[Any]) -> list[rules.Match]:
        """Gated scan: same matches as the full scan, fewer regex runs."""
        combined_text = "\n".join(_item_text(i) for i in items)
        if not combined_text:
            return []
        return rules.scan(combined_text, guard="context", gated=True, extended=self._extended)
