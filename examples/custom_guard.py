from __future__ import annotations

import time

from enums import Decision, GuardExecutionStatus, Stage
from schemas import RuntimeObservation, SecurityContext, SecurityResult

from security.plugins.interface import GuardPlugin


class CustomKeywordGuard(GuardPlugin):
    name = "custom_keyword_guard"
    stage = Stage.INPUT

    def inspect(
        self,
        observation: RuntimeObservation,
        context: SecurityContext,
    ) -> SecurityResult:
        start = time.perf_counter()

        text = (observation.user_input or "").lower()
        matched = "restricted-demo-token" in text

        return SecurityResult(
            run_id=observation.run_id,
            trace_id=observation.trace_id,
            stage=self.stage,
            guard_name=self.name,
            execution_status=GuardExecutionStatus.SUCCESS,
            risk_score=0.8 if matched else 0.0,
            decision=Decision.WARN if matched else Decision.ALLOW,
            rule_ids=["custom.keyword_match"] if matched else [],
            evidence=[{"matched_keyword": "restricted-demo-token"}]
            if matched
            else [],
            latency_ms=(time.perf_counter() - start) * 1000,
        )
