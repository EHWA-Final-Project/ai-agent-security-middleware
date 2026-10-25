"""Security Orchestrator.

Owns SecurityContext for a run and runs the full Input -> Context ->
(Tool) -> Output stage sequence internally within a single evaluate() call.
Callers invoke evaluate() once per turn; stage-to-stage transitions and
WARN/STRICT escalation happen inside this class.

Behavior notes:
  - TOOL stage (and therefore EnforcementInterface.enforce()) only runs
    when observation.tool_candidate is not None. A pure Input/Context-only
    turn never touches Enforcement.
  - enforce() is called at most once per run, at the Tool Decision point,
    covering both ALLOW (Tool stage cleared) and BLOCK (produced at or
    before Tool stage). A later BLOCK at Output stage does not re-invoke
    Enforcement, since tool execution has already completed by then.
  - WARN handling follows the frozen P0/P1 Decision policy: STANDARD+WARN
    escalates inspection mode only; STRICT+WARN behaves per stage
    (Input/Context accumulate and continue, Tool escalates to BLOCK,
    Output gets one sanitize-and-recheck attempt before BLOCK).
  - Critical Rule violations and cumulative_risk_score crossing
    block_threshold trigger an immediate BLOCK, checked after every guard
    result rather than only at the end of the run.
  - Orchestrator-internal failures raise OrchestratorInternalError so
    callers can distinguish an internal bug from a normal decision.
  - Evidence recording failures do not crash evaluate(); the computed
    SecurityDecision is still returned, and the failure is exposed via
    `orchestrator.last_evidence_error`.

Output stage input: the ExecutionResult returned by Enforcement at the Tool
Decision point is stored on the SecurityContext, so Output Guard inspects the
real tool output (P0 scope: tool output only, not the eventual final LLM
response).
"""

from __future__ import annotations

import concurrent.futures
import time
from dataclasses import dataclass, field

from contracts import EnforcementInterface, EvidenceSink
from enums import Decision, GuardExecutionStatus, InspectionMode, Stage
from errors import ErrorDetail
from schemas import (
    RuntimeObservation,
    SecurityContext,
    SecurityDecision,
    SecurityResult,
)

from security.orchestrator.fallback import apply_guard_fallback, is_guard_failure
from security.plugins.interface import GuardPlugin
from security.plugins.manager import PluginManager
from security.policy.config import CoordinationMode, PolicyConfig

_DEFAULT_GUARD_TIMEOUT_SEC = 2.0

_BASE_STAGE_ORDER = [Stage.INPUT, Stage.CONTEXT]
_OUTPUT_STAGE = Stage.OUTPUT


class OrchestratorInternalError(Exception):
    """Raised for Orchestrator-side failures NOT caused by any Guard (e.g.
    a bug in risk aggregation). Distinct from Guard failures, which are
    always handled via Guard Failure Isolation and never raise. Runtime
    should catch this specifically and map it to RunStatus=FAILED +
    ErrorDetail, rather than receiving a raw, unclassified exception.
    """

    def __init__(
        self,
        message: str,
        *,
        run_id: str,
        trace_id: str,
        original: Exception | None = None,
    ) -> None:
        super().__init__(message)
        self.run_id = run_id
        self.trace_id = trace_id
        self.original = original



@dataclass
class EvaluationTiming:
    """Wall-clock breakdown of the last evaluate() call (milliseconds).

    Not part of any shared contract: Runtime/Evaluation may read it from the
    Orchestrator the same way they read ``last_evidence_error``.

    evaluate_ms     whole evaluate() call
    guard_wall_ms   (guard name, wall time) per Guard call, measured here and
                    including thread hand-off; compare with the Guard's own
                    SecurityResult.latency_ms
    enforcement_ms  time inside Enforcement.enforce() (the tool itself runs here)
    evidence_ms     time spent in evidence_sink.record_result/record_decision
    security_core_ms  evaluate_ms minus enforcement_ms and evidence_ms, i.e.
                    Guards + Orchestrator logic only
    """

    evaluate_ms: float = 0.0
    enforcement_ms: float = 0.0
    evidence_ms: float = 0.0
    guard_wall_ms: list[tuple[str, float]] = field(default_factory=list)

    @property
    def guard_wall_total_ms(self) -> float:
        return sum(ms for _, ms in self.guard_wall_ms)

    @property
    def security_core_ms(self) -> float:
        return max(self.evaluate_ms - self.enforcement_ms - self.evidence_ms, 0.0)


class SecurityOrchestrator:
    def __init__(
        self,
        plugin_manager: PluginManager,
        policy_config: PolicyConfig,
        enforcement: EnforcementInterface,
        evidence_sink: EvidenceSink,
        *,
        guard_timeout_sec: float = _DEFAULT_GUARD_TIMEOUT_SEC,
    ) -> None:
        self.plugin_manager = plugin_manager
        self.policy_config = policy_config
        self.enforcement = enforcement
        self.evidence_sink = evidence_sink
        self.guard_timeout_sec = guard_timeout_sec
        #: Set by _safe_record_result/_safe_record_decision if evidence_sink
        #: raises. Runtime may inspect this after evaluate() returns to
        #: decide RunStatus=PARTIAL_FAILURE. Reset at the start of every
        #: evaluate() call.
        self.last_evidence_error: ErrorDetail | None = None
        #: Timing breakdown of the most recent evaluate() call (see EvaluationTiming).
        self.last_timing = EvaluationTiming()
        # Reused across every guard call so a timed-out guard's leftover
        # thread never blocks evaluate() — see _run_guard_safely.
        self._guard_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)

    # ------------------------------------------------------------------
    # Public entrypoint
    # ------------------------------------------------------------------

    def evaluate(self, observation: RuntimeObservation) -> SecurityDecision:
        self.last_evidence_error = None
        self.last_timing = EvaluationTiming()
        start = time.perf_counter()
        try:
            return self._evaluate(observation)
        except OrchestratorInternalError:
            raise
        except Exception as exc:
            raise OrchestratorInternalError(
                f"Unhandled Orchestrator failure: {exc}",
                run_id=observation.run_id,
                trace_id=observation.trace_id,
                original=exc,
            ) from exc
        finally:
            self.last_timing.evaluate_ms = (time.perf_counter() - start) * 1000

    # ------------------------------------------------------------------
    # Core flow
    # ------------------------------------------------------------------

    def _evaluate(self, observation: RuntimeObservation) -> SecurityDecision:
        context = SecurityContext(
            run_id=observation.run_id,
            trace_id=observation.trace_id,
            current_stage=Stage.INPUT,
            inspection_mode=InspectionMode.STANDARD,
            policy_version=self.policy_config.policy_version,
        )

        has_tool_candidate = observation.tool_candidate is not None
        stages = list(_BASE_STAGE_ORDER)
        if has_tool_candidate:
            stages.append(Stage.TOOL)
        stages.append(_OUTPUT_STAGE)

        # Enforcement fires at most once per run, at the Tool Decision
        # point. A BLOCK produced later at OUTPUT stage does not
        # re-invoke Enforcement since the tool call has already run.
        for stage in stages:
            context.current_stage = stage
            early_decision = self._run_stage(stage, observation, context)
            if early_decision is not None:
                if has_tool_candidate and stage in (Stage.INPUT, Stage.CONTEXT, Stage.TOOL):
                    self._safe_enforce(early_decision, context)
                return self._finalize_record_only(early_decision)

            if stage == Stage.TOOL:
                # Tool Decision point: TOOL stage cleared with no BLOCK ->
                # ALLOW. Enforcement is called here, once, so Runtime can
                # actually execute the tool before OUTPUT stage runs.
                # The returned ExecutionResult is stored on context so
                # Output Guard can inspect the real tool output (P0 scope:
                # tool output only, not the eventual final LLM response).
                interim_decision = self._decision_from_context(
                    observation, context, decision=Decision.ALLOW,
                    reason="TOOL stage cleared, proceeding to execution",
                )
                self._safe_enforce(interim_decision, context)

        # All stages cleared without an early BLOCK (or the only BLOCK was
        # at OUTPUT stage, already handled above via early_decision).
        if self._independent:
            return self._finalize_record_only(self._decide_independent(observation, context))

        final_risk = self._aggregate_risk(context.previous_results)
        context.cumulative_risk_score = final_risk
        final_decision = self._decide_from_risk(observation, context, final_risk)
        # sanitized_output only ever reaches Runtime on a final ALLOW —
        # WARN and BLOCK both withhold it regardless of whether
        # sanitization ran, per the agreed Runtime output-usage rule.
        if final_decision.decision == Decision.ALLOW and context.pending_sanitized_output is not None:
            final_decision.sanitized_output = context.pending_sanitized_output
        return self._finalize_record_only(final_decision)

    def _run_stage(
        self,
        stage: Stage,
        observation: RuntimeObservation,
        context: SecurityContext,
    ) -> SecurityDecision | None:
        """Run all guards registered for `stage`. Returns a SecurityDecision
        if the stage produced an early BLOCK (caller should stop and
        finalize with it); returns None if the stage cleared normally.
        """
        guards = self.plugin_manager.guards_for_stage(stage)

        for guard in guards:
            result = self._run_guard_safely(guard, observation, context)
            context.previous_results.append(result)
            self._safe_record_result(result)

            if is_guard_failure(result):
                next_mode, fallback_decision = apply_guard_fallback(
                    result,
                    current_mode=context.inspection_mode,
                    policy_version=context.policy_version,
                )
                if not self._independent:
                    context.inspection_mode = next_mode
                if fallback_decision is not None:
                    return fallback_decision
                continue

            # Critical Rule violation: immediate BLOCK regardless of stage.
            if any(self.policy_config.is_critical_rule(rid) for rid in result.rule_ids):
                return self._decision_from_context(
                    observation, context, decision=Decision.BLOCK,
                    reason=f"Critical rule violated: {result.rule_ids}",
                    rule_ids=result.rule_ids,
                )

            # A Guard directly returning BLOCK stops the run immediately.
            if result.decision == Decision.BLOCK:
                return self._decision_from_context(
                    observation, context, decision=Decision.BLOCK,
                    reason=f"Guard '{guard.name}' returned BLOCK",
                    rule_ids=result.rule_ids,
                )

            if self._independent:
                early_decision = self._judge_independently(guard, result, observation, context)
                if early_decision is not None:
                    return early_decision
                continue

            # Cumulative risk is recomputed and checked against
            # block_threshold after EVERY successful guard result,
            # regardless of that guard's own decision — several ALLOW
            # results can combine (via noisy-OR) to cross block_threshold
            # even when no single guard said WARN or BLOCK.
            context.cumulative_risk_score = self._aggregate_risk(context.previous_results)
            if context.cumulative_risk_score >= self.policy_config.block_threshold:
                return self._decision_from_context(
                    observation, context, decision=Decision.BLOCK,
                    reason=(
                        f"cumulative_risk_score {context.cumulative_risk_score:.2f} "
                        "exceeded block_threshold"
                    ),
                )

            if result.decision == Decision.WARN:
                early_decision = self._handle_warn(guard, stage, observation, context)
                if early_decision is not None:
                    return early_decision

            # ALLOW: nothing special, continue to next guard/stage.

        return None

    @property
    def _independent(self) -> bool:
        return self.policy_config.coordination_mode == CoordinationMode.INDEPENDENT

    def _judge_independently(
        self,
        guard: GuardPlugin,
        result: SecurityResult,
        observation: RuntimeObservation,
        context: SecurityContext,
    ) -> SecurityDecision | None:
        """INDEPENDENT mode: this guard's own risk_score is compared to the
        thresholds on its own. No accumulation across guards, no inspection
        mode escalation, no sanitize retry. BLOCK returns immediately; a
        WARN-level score is picked up later by _decide_independent.
        """
        risk = result.risk_score or 0.0
        context.cumulative_risk_score = max(context.cumulative_risk_score, risk)
        if risk >= self.policy_config.block_threshold:
            return self._decision_from_context(
                observation, context, decision=Decision.BLOCK,
                reason=(
                    f"independent mode: guard '{guard.name}' risk_score {risk:.2f} "
                    "exceeded block_threshold"
                ),
            )
        return None

    def _decide_independent(
        self,
        observation: RuntimeObservation,
        context: SecurityContext,
    ) -> SecurityDecision:
        """Final decision in INDEPENDENT mode: the worst single-guard level.
        BLOCK never reaches here (returned early). Nothing accumulates, so
        cumulative_risk_score holds the highest single-guard risk.
        """
        scored = [
            r for r in context.previous_results
            if r.execution_status == GuardExecutionStatus.SUCCESS and r.risk_score is not None
        ]
        top = max(scored, key=lambda r: r.risk_score, default=None)
        context.cumulative_risk_score = top.risk_score if top is not None else 0.0

        if top is not None and top.risk_score >= self.policy_config.strict_threshold:
            return self._decision_from_context(
                observation, context, decision=Decision.WARN,
                reason=(
                    f"independent mode: guard '{top.guard_name}' risk_score "
                    f"{top.risk_score:.2f} exceeded strict_threshold"
                ),
            )
        return self._decision_from_context(
            observation, context, decision=Decision.ALLOW,
            reason="no guard exceeded policy thresholds",
        )

    def _handle_warn(
        self,
        guard: GuardPlugin,
        stage: Stage,
        observation: RuntimeObservation,
        context: SecurityContext,
    ) -> SecurityDecision | None:
        """P0/P1 Decision 원칙:
          STANDARD + WARN -> escalate next guard to STRICT.
          STRICT + WARN, Input/Context -> continue (no BLOCK yet).
          STRICT + WARN, Tool -> escalate to BLOCK, 0 tool executions.
          STRICT + WARN, Output -> one sanitize-and-recheck attempt, then
            BLOCK if still WARN/BLOCK.
        Cumulative risk / block_threshold is already checked unconditionally
        in _run_stage before this is called — this method only handles mode
        escalation and stage-specific STRICT behavior.
        """
        if context.inspection_mode == InspectionMode.STANDARD:
            context.inspection_mode = InspectionMode.STRICT
            return None

        # inspection_mode is STRICT from here on.
        if stage in (Stage.INPUT, Stage.CONTEXT):
            return None  # accumulate and continue, no BLOCK yet

        if stage == Stage.TOOL:
            return self._decision_from_context(
                observation, context, decision=Decision.BLOCK,
                reason=f"STRICT+WARN at TOOL stage escalated to BLOCK ('{guard.name}')",
            )

        # stage == OUTPUT: one sanitize-and-recheck attempt.
        sanitized_result = self._attempt_output_sanitization(guard, observation, context)
        context.previous_results.append(sanitized_result)
        self._safe_record_result(sanitized_result)

        context.cumulative_risk_score = self._aggregate_risk(context.previous_results)
        if context.cumulative_risk_score >= self.policy_config.block_threshold:
            return self._decision_from_context(
                observation, context, decision=Decision.BLOCK,
                reason=(
                    f"cumulative_risk_score {context.cumulative_risk_score:.2f} "
                    "exceeded block_threshold after sanitization"
                ),
            )

        if is_guard_failure(sanitized_result) or sanitized_result.decision in (
            Decision.WARN,
            Decision.BLOCK,
        ):
            return self._decision_from_context(
                observation, context, decision=Decision.BLOCK,
                reason="Output still WARN/BLOCK after one sanitization attempt",
            )

        # Sanitization resolved it — stash the redacted tool-output text so
        # the final SecurityDecision can carry it, but ONLY if the run
        # ultimately ends in ALLOW (checked at the point the final decision
        # is built, not here).
        if sanitized_result.evidence:
            context.pending_sanitized_output = sanitized_result.evidence[0].get("sanitized_output")
        return None  # sanitization resolved it; continue

    def _attempt_output_sanitization(
        self,
        guard: GuardPlugin,
        observation: RuntimeObservation,
        context: SecurityContext,
    ) -> SecurityResult:
        """Calls the Guard's sanitize() instead of inspect() — Output Guard
        implements real redaction here; Guards without redaction support
        fall back to GuardPlugin's default (re-check as-is).
        """
        return self._run_guard_safely(guard, observation, context, method="sanitize")

    # ------------------------------------------------------------------
    # Guard execution (timeout + error isolation)
    # ------------------------------------------------------------------

    def _run_guard_safely(
        self,
        guard: GuardPlugin,
        observation: RuntimeObservation,
        context: SecurityContext,
        *,
        method: str = "inspect",
    ) -> SecurityResult:
        start = time.perf_counter()
        try:
            return self._call_guard(guard, observation, context, method=method)
        finally:
            self.last_timing.guard_wall_ms.append(
                (guard.name, (time.perf_counter() - start) * 1000)
            )

    def _call_guard(
        self,
        guard: GuardPlugin,
        observation: RuntimeObservation,
        context: SecurityContext,
        *,
        method: str = "inspect",
    ) -> SecurityResult:
        start = time.perf_counter()
        target = getattr(guard, method)
        future = self._guard_executor.submit(target, observation, context)
        try:
            return future.result(timeout=self.guard_timeout_sec)
        except concurrent.futures.TimeoutError:
            latency_ms = (time.perf_counter() - start) * 1000
            return SecurityResult(
                run_id=observation.run_id,
                trace_id=observation.trace_id,
                stage=guard.stage,
                guard_name=guard.name,
                execution_status=GuardExecutionStatus.TIMEOUT,
                latency_ms=latency_ms,
                error=ErrorDetail(
                    code="guard_timeout",
                    message=f"Guard '{guard.name}' exceeded {self.guard_timeout_sec}s",
                    stage=guard.stage,
                    retryable=True,
                    trace_id=observation.trace_id,
                ),
            )
        except Exception as exc:  # noqa: BLE001 — intentional boundary catch
            latency_ms = (time.perf_counter() - start) * 1000
            return SecurityResult(
                run_id=observation.run_id,
                trace_id=observation.trace_id,
                stage=guard.stage,
                guard_name=guard.name,
                execution_status=GuardExecutionStatus.ERROR,
                latency_ms=latency_ms,
                error=ErrorDetail(
                    code="guard_execution_error",
                    message=str(exc),
                    stage=guard.stage,
                    retryable=False,
                    trace_id=observation.trace_id,
                ),
            )

    def close(self) -> None:
        """Release the shared guard-execution thread pool. A timed-out
        guard's underlying thread cannot be forcibly killed (a Python
        limitation), so it is left to finish in the background rather than
        blocking this call.
        """
        self._guard_executor.shutdown(wait=False)

    # ------------------------------------------------------------------
    # Risk aggregation & decision construction
    # ------------------------------------------------------------------

    def _aggregate_risk(self, results: list[SecurityResult]) -> float:
        """Noisy-OR: R_total = 1 - Π(1 - w_i * R_i), over successful results
        with a non-null risk_score only. Failed guards (risk_score=None)
        are excluded — their consequence is already handled via fallback.
        """
        product = 1.0
        for result in results:
            if result.execution_status != GuardExecutionStatus.SUCCESS:
                continue
            if result.risk_score is None:
                continue
            weight = self.policy_config.weight_for(result.guard_name)
            product *= 1 - (weight * result.risk_score)
        return 1 - product

    def _decision_from_context(
        self,
        observation: RuntimeObservation,
        context: SecurityContext,
        *,
        decision: Decision,
        reason: str,
        rule_ids: list[str] | None = None,
    ) -> SecurityDecision:
        return SecurityDecision(
            run_id=observation.run_id,
            trace_id=observation.trace_id,
            decision=decision,
            reason=reason,
            triggered_rules=list(rule_ids) if rule_ids else [
                rid for r in context.previous_results for rid in r.rule_ids
            ],
            cumulative_risk_score=context.cumulative_risk_score,
            policy_version=context.policy_version,
        )

    def _decide_from_risk(
        self,
        observation: RuntimeObservation,
        context: SecurityContext,
        cumulative_risk: float,
    ) -> SecurityDecision:
        if cumulative_risk >= self.policy_config.block_threshold:
            decision = Decision.BLOCK
            reason = f"cumulative_risk_score {cumulative_risk:.2f} exceeded block_threshold"
        elif cumulative_risk >= self.policy_config.strict_threshold:
            decision = Decision.WARN
            reason = f"cumulative_risk_score {cumulative_risk:.2f} exceeded strict_threshold"
        else:
            decision = Decision.ALLOW
            reason = "no guard exceeded policy thresholds"

        return self._decision_from_context(observation, context, decision=decision, reason=reason)

    # ------------------------------------------------------------------
    # Contract boundary calls (Enforcement / Evidence), isolated so a
    # failure on either side has a defined, non-crashing behavior.
    # ------------------------------------------------------------------

    def _finalize_record_only(self, decision: SecurityDecision) -> SecurityDecision:
        """Records the final decision to Evidence. Does NOT call Enforcement
        — enforcement (if any) has already happened exactly once, inline in
        _evaluate(), at the Tool Decision point.
        """
        self._safe_record_decision(decision)
        return decision

    def _safe_enforce(self, decision: SecurityDecision, context: SecurityContext) -> None:
        start = time.perf_counter()
        try:
            execution_result = self.enforcement.enforce(decision)
        finally:
            self.last_timing.enforcement_ms += (time.perf_counter() - start) * 1000
        context.execution_result = execution_result

    def _safe_record_result(self, result: SecurityResult) -> None:
        start = time.perf_counter()
        try:
            self.evidence_sink.record_result(result)
        except Exception as exc:  # noqa: BLE001 — evidence failures must not crash a valid decision
            self.last_evidence_error = ErrorDetail(
                code="evidence_record_result_failed",
                message=str(exc),
                stage=result.stage,
                retryable=True,
                trace_id=result.trace_id,
            )
        finally:
            self.last_timing.evidence_ms += (time.perf_counter() - start) * 1000

    def _safe_record_decision(self, decision: SecurityDecision) -> None:
        start = time.perf_counter()
        try:
            self.evidence_sink.record_decision(decision)
        except Exception as exc:  # noqa: BLE001 — evidence failures must not crash a valid decision
            self.last_evidence_error = ErrorDetail(
                code="evidence_record_decision_failed",
                message=str(exc),
                stage=None,
                retryable=True,
                trace_id=decision.trace_id,
            )
        finally:
            self.last_timing.evidence_ms += (time.perf_counter() - start) * 1000
