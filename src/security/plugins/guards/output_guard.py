"""Output Guard · P0 baseline.
"""

from __future__ import annotations

import re
import time
from typing import Any

from enums import AttackSubtype, Decision, GuardExecutionStatus, Stage
from schemas.runtime import RuntimeObservation
from schemas.security import SecurityContext, SecurityResult

from security.plugins.guards._tool_names import base_tool_name
from security.plugins.interface import GuardPlugin

_SECRET_PATTERNS = [
    r"api[_-]?key\s*[:=]\s*\S+",
    r"password\s*[:=]\s*\S+",
    r"secret[_-]?key\s*[:=]\s*\S+",
    r"-----BEGIN [A-Z ]+PRIVATE KEY-----",
]

#: tool_name -> key in ExecutionResult.output holding checkable text.
#: A tool not listed here is treated as having nothing to check.
#: Looked up by base name, so ``demo/read_file`` is checked like ``read_file``.
_TOOL_TEXT_KEY = {
    "read_file": "content",
}


def _redact(text: str) -> str:
    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = re.sub(pattern, "[REDACTED]", redacted, flags=re.IGNORECASE)
    return redacted


def _tool_output_text(context: SecurityContext) -> str | None:
    """Extract the checkable text from ExecutionResult.output, using the
    tool-specific key from _TOOL_TEXT_KEY. Returns None if there's no
    execution_result, no output, or the tool has no known checkable-text
    key (e.g. send_email — metadata only).
    """
    if context.execution_result is None or context.execution_result.output is None:
        return None
    output: Any = context.execution_result.output
    if not isinstance(output, dict):
        # Back-compat: a plain string result, no tool-specific key needed.
        return str(output)

    tool_name = context.execution_result.tool_name
    text_key = _TOOL_TEXT_KEY.get(base_tool_name(tool_name) or "")
    if text_key is None:
        return None
    text = output.get(text_key)
    return str(text) if text is not None else None


def _context_items_text(observation: RuntimeObservation) -> str | None:
    if not observation.context_items:
        return None
    return " ".join(str(item) for item in observation.context_items)


def _matches(text: str) -> list[str]:
    return [p for p in _SECRET_PATTERNS if re.search(p, text, re.IGNORECASE)]


def _allow_result(
    observation: RuntimeObservation,
    latency_ms: float,
    *,
    checked_sources: list[str] | None = None,
) -> SecurityResult:
    return SecurityResult(
        run_id=observation.run_id,
        trace_id=observation.trace_id,
        stage=Stage.OUTPUT,
        guard_name="output_guard",
        execution_status=GuardExecutionStatus.SUCCESS,
        risk_score=0.0,
        decision=Decision.ALLOW,
        # evidence=[] means genuinely nothing existed to check (e.g. a
        # no-tool turn with empty context_items). evidence=[{"checked_sources":
        # [...]}] means one or more sources were present and actually
        # checked, and came back clean — distinct from "never checked".
        evidence=[{"checked_sources": checked_sources}] if checked_sources else [],
        latency_ms=latency_ms,
    )


class OutputGuard(GuardPlugin):
    name = "output_guard"
    stage = Stage.OUTPUT

    def inspect(self, observation: RuntimeObservation, context: SecurityContext) -> SecurityResult:
        start = time.perf_counter()
        tool_text = _tool_output_text(context)
        context_text = _context_items_text(observation)

        if tool_text is None and context_text is None:
            return _allow_result(observation, (time.perf_counter() - start) * 1000)

        present_sources = []
        if tool_text is not None:
            present_sources.append("tool_output")
        if context_text is not None:
            present_sources.append("context_items")

        matched_by_source: dict[str, list[str]] = {}
        if tool_text is not None:
            hits = _matches(tool_text)
            if hits:
                matched_by_source["tool_output"] = hits
        if context_text is not None:
            hits = _matches(context_text)
            if hits:
                matched_by_source["context_items"] = hits

        latency_ms = (time.perf_counter() - start) * 1000
        if matched_by_source:
            return SecurityResult(
                run_id=observation.run_id,
                trace_id=observation.trace_id,
                stage=self.stage,
                guard_name=self.name,
                execution_status=GuardExecutionStatus.SUCCESS,
                risk_score=0.95,
                decision=Decision.WARN,
                rule_ids=["output_guard.secret_leakage"],
                evidence=[
                    {
                        "matched_by_source": matched_by_source,
                        "attack_subtype": AttackSubtype.DATA_LEAKAGE.value,
                    }
                ],
                latency_ms=latency_ms,
            )

        return _allow_result(observation, latency_ms, checked_sources=present_sources)

    def sanitize(self, observation: RuntimeObservation, context: SecurityContext) -> SecurityResult:
        """Redacts and re-checks both sources. sanitized_output in the
        returned evidence is ALWAYS set to the redacted tool_output text
        whenever a tool_output source existed (even if nothing needed
        redacting — the text is still echoed back as the attempted
        result), so Runtime can distinguish "attempted, here's the safe
        text" (possibly unchanged, possibly empty string) from "never
        attempted" (None, when there was no tool_output source at all).
        context_items redaction is checked but never surfaced as
        sanitized_output — Runtime never forwards raw context_items
        downstream, so there is nothing for it to substitute there.
        """
        start = time.perf_counter()
        tool_text = _tool_output_text(context)
        context_text = _context_items_text(observation)

        if tool_text is None and context_text is None:
            return _allow_result(observation, (time.perf_counter() - start) * 1000)

        still_matched: dict[str, list[str]] = {}
        sanitized_tool_output: str | None = None

        if tool_text is not None:
            redacted_tool = _redact(tool_text)
            sanitized_tool_output = redacted_tool
            hits = _matches(redacted_tool)
            if hits:
                still_matched["tool_output"] = hits

        if context_text is not None:
            redacted_context = _redact(context_text)
            hits = _matches(redacted_context)
            if hits:
                still_matched["context_items"] = hits

        latency_ms = (time.perf_counter() - start) * 1000

        if still_matched:
            return SecurityResult(
                run_id=observation.run_id,
                trace_id=observation.trace_id,
                stage=self.stage,
                guard_name=self.name,
                execution_status=GuardExecutionStatus.SUCCESS,
                risk_score=0.95,
                decision=Decision.WARN,
                rule_ids=["output_guard.secret_leakage"],
                evidence=[{"still_matched_after_redaction": still_matched}],
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
            evidence=[{"sanitized": True, "sanitized_output": sanitized_tool_output}],
            latency_ms=latency_ms,
        )
