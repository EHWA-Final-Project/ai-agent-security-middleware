"""Tool Guard · P0 baseline.

This guard only ever runs when observation.tool_candidate is present,
since the Orchestrator does not include Stage.TOOL in a no-tool turn.
"""

from __future__ import annotations

import time

from enums import AttackSubtype, Decision, GuardExecutionStatus, Stage
from schemas import RuntimeObservation, SecurityContext, SecurityResult

from security.plugins.interface import GuardPlugin

_SENSITIVE_TOOLS = {
    "send_email",
    "transfer_funds",
    "delete_file",
    "execute_code",
}


class ToolGuard(GuardPlugin):
    name = "tool_guard"
    stage = Stage.TOOL

    def inspect(self, observation: RuntimeObservation, context: SecurityContext) -> SecurityResult:
        start = time.perf_counter()

        tool_candidate = observation.tool_candidate or {}
        tool_name = tool_candidate.get("tool_name")
        latency_ms = (time.perf_counter() - start) * 1000

        if tool_name in _SENSITIVE_TOOLS:
            return SecurityResult(
                run_id=observation.run_id,
                trace_id=observation.trace_id,
                stage=self.stage,
                guard_name=self.name,
                execution_status=GuardExecutionStatus.SUCCESS,
                risk_score=0.6,
                decision=Decision.WARN,
                rule_ids=["tool_guard.sensitive_tool_invocation"],
                evidence=[
                    {
                        "tool_name": tool_name,
                        "attack_subtype": AttackSubtype.TOOL_MISUSE.value,
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
