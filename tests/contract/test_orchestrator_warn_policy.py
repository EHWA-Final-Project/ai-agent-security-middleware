from enums import Decision, ExecutionState, GuardExecutionStatus, Stage
from fixtures import mock_runtime_observation
from schemas import ExecutionResult, SecurityContext, SecurityResult

from security.orchestrator.orchestrator import (
    OrchestratorInternalError,
    SecurityOrchestrator,
)
from security.plugins.interface import GuardPlugin
from security.plugins.manager import PluginManager
from security.policy.config import PolicyConfig


class _RecordingEnforcement:
    def __init__(self) -> None:
        self.calls: list = []

    def enforce(self, decision) -> ExecutionResult | None:
        self.calls.append(decision)
        executed = decision.decision == Decision.ALLOW
        return ExecutionResult(
            run_id=decision.run_id,
            trace_id=decision.trace_id,
            tool_call_id="tool-call-1",
            tool_name="mock_tool",
            execution_state=ExecutionState.EXECUTED if executed else ExecutionState.BLOCKED,
            executed=executed,
            output="mock tool output" if executed else None,
            latency_ms=5.0,
        )


class _RecordingEvidenceSink:
    def __init__(self) -> None:
        self.results: list[SecurityResult] = []
        self.decisions: list = []

    def record_result(self, result: SecurityResult) -> None:
        self.results.append(result)

    def record_decision(self, decision) -> None:
        self.decisions.append(decision)


class _FailingEvidenceSink(_RecordingEvidenceSink):
    def record_result(self, result: SecurityResult) -> None:
        raise ConnectionError("evidence store unreachable")


class _FixedGuard(GuardPlugin):
    """Test double returning a fixed WARN/BLOCK/ALLOW decision + risk_score,
    for exercising the WARN/STRICT escalation ladder deterministically.
    """

    def __init__(self, name: str, stage: Stage, decision: Decision, risk_score: float, rule_ids=None):
        self.name = name
        self.stage = stage
        self._decision = decision
        self._risk_score = risk_score
        self._rule_ids = rule_ids or []

    def inspect(self, observation, context: SecurityContext) -> SecurityResult:
        return SecurityResult(
            run_id=observation.run_id,
            trace_id=observation.trace_id,
            stage=self.stage,
            guard_name=self.name,
            execution_status=GuardExecutionStatus.SUCCESS,
            risk_score=self._risk_score,
            decision=self._decision,
            rule_ids=self._rule_ids,
            latency_ms=1.0,
        )


class _BuggyOrchestratorPieceGuard(GuardPlugin):
    """A guard whose result deliberately has an inconsistent risk_score to
    probe that non-guard internal bugs are classified as
    OrchestratorInternalError, not a raw exception. Also reused as an
    'unreachable guard' stand-in — should never run if an earlier stage
    already produced BLOCK.
    """

    name = "unreachable_guard"
    stage = Stage.CONTEXT

    def inspect(self, observation, context: SecurityContext) -> SecurityResult:
        return SecurityResult(
            run_id=observation.run_id,
            trace_id=observation.trace_id,
            stage=self.stage,
            guard_name=self.name,
            execution_status=GuardExecutionStatus.SUCCESS,
            risk_score=0.1,
            decision=Decision.ALLOW,
            latency_ms=1.0,
        )


def _build(evidence_sink=None, *, policy: PolicyConfig | None = None):
    manager = PluginManager()
    policy = policy or PolicyConfig(
        policy_version="v0.1.0-p0-baseline", strict_threshold=0.30, block_threshold=0.90
    )
    enforcement = _RecordingEnforcement()
    evidence = evidence_sink or _RecordingEvidenceSink()
    orchestrator = SecurityOrchestrator(
        plugin_manager=manager, policy_config=policy, enforcement=enforcement, evidence_sink=evidence,
    )
    return orchestrator, enforcement, evidence, manager


def test_standard_warn_escalates_mode_and_continues():
    """STANDARD + WARN -> accumulate risk, next guard runs under STRICT, no BLOCK yet."""
    orchestrator, _enf, _ev, manager = _build()
    manager.register_guard(_FixedGuard("input_guard", Stage.INPUT, Decision.WARN, 0.4))
    # Second WARN at CONTEXT stage, now under STRICT — Input/Context WARN
    # under STRICT still doesn't block, per policy.
    manager.register_guard(_FixedGuard("context_guard", Stage.CONTEXT, Decision.WARN, 0.2))

    observation = mock_runtime_observation()
    decision = orchestrator.evaluate(observation)

    # Neither WARN alone crosses block_threshold=0.90 given noisy-OR combination
    # of 0.4 and 0.2 (~0.52), so run completes as WARN overall, not BLOCK.
    assert decision.decision == Decision.WARN


def test_strict_warn_at_tool_stage_escalates_to_block():
    orchestrator, enforcement, _ev, manager = _build()
    # First WARN (STANDARD->STRICT) at INPUT with low risk so it doesn't
    # itself cross block_threshold.
    manager.register_guard(_FixedGuard("input_guard", Stage.INPUT, Decision.WARN, 0.35))
    # Second WARN, now under STRICT, at TOOL stage -> must escalate to BLOCK.
    manager.register_guard(_FixedGuard("tool_guard", Stage.TOOL, Decision.WARN, 0.1))

    observation = mock_runtime_observation(tool_candidate={"tool_name": "send_email"})
    decision = orchestrator.evaluate(observation)

    assert decision.decision == Decision.BLOCK
    assert "STRICT+WARN at TOOL stage" in decision.reason
    assert len(enforcement.calls) == 1
    assert enforcement.calls[0].decision == Decision.BLOCK


def test_strict_warn_at_output_stage_calls_sanitize_not_inspect_again():
    """The retry on STRICT+WARN at OUTPUT must call guard.sanitize(), not
    guard.inspect() a second time — proves real redaction is wired in, not
    the old placeholder (identical re-check) behavior.
    """
    orchestrator, _enforcement, _ev, manager = _build()
    manager.register_guard(_FixedGuard("input_guard", Stage.INPUT, Decision.WARN, 0.35))

    class _TrackingOutputGuard(GuardPlugin):
        name = "output_guard"
        stage = Stage.OUTPUT

        def __init__(self) -> None:
            self.inspect_calls = 0
            self.sanitize_calls = 0

        def inspect(self, observation, context) -> SecurityResult:
            self.inspect_calls += 1
            return SecurityResult(
                run_id=observation.run_id, trace_id=observation.trace_id,
                stage=self.stage, guard_name=self.name,
                execution_status=GuardExecutionStatus.SUCCESS,
                risk_score=0.4, decision=Decision.WARN, latency_ms=1.0,
            )

        def sanitize(self, observation, context) -> SecurityResult:
            self.sanitize_calls += 1
            return SecurityResult(
                run_id=observation.run_id, trace_id=observation.trace_id,
                stage=self.stage, guard_name=self.name,
                execution_status=GuardExecutionStatus.SUCCESS,
                risk_score=0.0, decision=Decision.ALLOW, latency_ms=1.0,
            )

    output_guard = _TrackingOutputGuard()
    manager.register_guard(output_guard)

    observation = mock_runtime_observation()
    orchestrator.evaluate(observation)

    assert output_guard.inspect_calls == 1
    assert output_guard.sanitize_calls == 1
    """STRICT + WARN at Input/Context must accumulate and continue, not BLOCK."""
    orchestrator, _enf, _ev, manager = _build()
    manager.register_guard(_FixedGuard("input_guard", Stage.INPUT, Decision.WARN, 0.35))
    manager.register_guard(_FixedGuard("context_guard", Stage.CONTEXT, Decision.WARN, 0.1))

    observation = mock_runtime_observation()
    decision = orchestrator.evaluate(observation)

    # Both WARNs accumulate via noisy-OR (~0.42), stays under block_threshold=0.90.
    assert decision.decision == Decision.WARN


def test_critical_rule_violation_blocks_immediately_regardless_of_stage():
    policy = PolicyConfig(
        policy_version="v0.1.0-p0-baseline",
        strict_threshold=0.30,
        block_threshold=0.90,
        critical_rule_ids=["critical.exfiltration_attempt"],
    )
    orchestrator, enforcement, _ev, manager = _build(policy=policy)
    # Low risk_score so threshold alone would NOT trigger BLOCK — only the
    # critical rule should.
    manager.register_guard(
        _FixedGuard(
            "input_guard", Stage.INPUT, Decision.WARN, 0.1,
            rule_ids=["critical.exfiltration_attempt"],
        )
    )

    observation = mock_runtime_observation(tool_candidate={"tool_name": "send_email"})
    decision = orchestrator.evaluate(observation)

    assert decision.decision == Decision.BLOCK
    assert "Critical rule violated" in decision.reason
    assert len(enforcement.calls) == 1


def test_block_threshold_crossed_immediately_not_deferred_to_end_of_run():
    """A single WARN whose risk alone crosses block_threshold must BLOCK
    right away, not wait until all stages finish.
    """
    orchestrator, _enf, _ev, manager = _build()
    manager.register_guard(_FixedGuard("input_guard", Stage.INPUT, Decision.WARN, 0.95))
    # This guard must never run — the run should have already BLOCKed.
    manager.register_guard(_BuggyOrchestratorPieceGuard())

    observation = mock_runtime_observation()
    decision = orchestrator.evaluate(observation)

    assert decision.decision == Decision.BLOCK
    assert "exceeded block_threshold" in decision.reason


def test_evidence_failure_does_not_crash_process_and_is_exposed():
    orchestrator, _enf, _evidence, manager = _build(evidence_sink=_FailingEvidenceSink())
    from security.plugins.guards.input_guard import InputGuard

    manager.register_guard(InputGuard())

    observation = mock_runtime_observation(user_input="Summarize this document for me.")
    decision = orchestrator.evaluate(observation)

    # The correctly-computed decision is still returned despite Evidence failing.
    assert decision.decision == Decision.ALLOW
    assert orchestrator.last_evidence_error is not None
    assert orchestrator.last_evidence_error.code == "evidence_record_result_failed"


def test_orchestrator_internal_bug_raises_typed_exception_not_raw():
    orchestrator, _enf, _ev, manager = _build()
    manager.register_guard(_BuggyOrchestratorPieceGuard())

    # Force an internal bug by breaking policy_config after construction,
    # simulating an Orchestrator-side defect unrelated to any Guard.
    orchestrator.policy_config = None  # type: ignore[assignment]

    observation = mock_runtime_observation(run_id="run-err-1", trace_id="trace-err-1")

    try:
        orchestrator.evaluate(observation)
        raise AssertionError("expected OrchestratorInternalError to be raised")
    except OrchestratorInternalError as exc:
        assert exc.run_id == "run-err-1"
        assert exc.trace_id == "trace-err-1"
        assert exc.original is not None


def test_cumulative_risk_from_multiple_allows_blocks_before_enforcement():
    """Regression test for a real bug found during 지원's integration
    check: three ALLOW results (risk 0.45 each) combine via noisy-OR to
    0.833625, which crosses block_threshold=0.80 — but since no single
    guard said WARN, the old code never re-checked cumulative risk and
    called enforce(ALLOW) at the Tool Decision point before the final BLOCK
    was computed at the very end. The fix checks cumulative risk after
    every successful guard result, so this must BLOCK at TOOL stage and
    enforce() must receive BLOCK, never ALLOW.
    """
    policy = PolicyConfig(policy_version="v0.1.0-p0-baseline", strict_threshold=0.50, block_threshold=0.80)
    orchestrator, enforcement, _ev, manager = _build(policy=policy)
    manager.register_guard(_FixedGuard("input_guard", Stage.INPUT, Decision.ALLOW, 0.45))
    manager.register_guard(_FixedGuard("context_guard", Stage.CONTEXT, Decision.ALLOW, 0.45))
    manager.register_guard(_FixedGuard("tool_guard", Stage.TOOL, Decision.ALLOW, 0.45))

    observation = mock_runtime_observation(tool_candidate={"tool_name": "send_email"})
    decision = orchestrator.evaluate(observation)

    assert decision.decision == Decision.BLOCK
    assert decision.cumulative_risk_score >= 0.80
    # Enforcement must never have been called with ALLOW.
    assert len(enforcement.calls) == 1
    assert enforcement.calls[0].decision == Decision.BLOCK


def test_guard_timeout_does_not_block_on_the_slow_guards_actual_duration():
    """Regression test for a real bug found during 지원's integration
    check: the old implementation created a ThreadPoolExecutor per guard
    call inside a `with` block, whose __exit__ calls shutdown(wait=True) —
    silently blocking until the timed-out guard's thread actually finished,
    defeating the point of the timeout. A 0.01s timeout against a 0.15s
    guard used to return after ~0.15s; it must now return close to 0.01s.
    """
    import time as _time

    class _SlowFixedGuard(GuardPlugin):
        name = "slow_guard"
        stage = Stage.INPUT

        def inspect(self, observation, context):
            _time.sleep(0.15)
            raise AssertionError("should never complete before the caller times out")

    orchestrator, _enf, _ev, _manager = _build()
    orchestrator.guard_timeout_sec = 0.01

    start = _time.perf_counter()
    result = orchestrator._run_guard_safely(
        _SlowFixedGuard(),
        mock_runtime_observation(),
        SecurityContext(
            run_id="r", trace_id="t", current_stage=Stage.INPUT, policy_version="v0.1.0-p0-baseline"
        ),
    )
    elapsed = _time.perf_counter() - start

    assert result.execution_status == GuardExecutionStatus.TIMEOUT
    # Bounded near the 0.01s timeout, not the guard's full 0.15s sleep.
    assert elapsed < 0.1, f"expected timeout to bound latency, took {elapsed:.3f}s"

    orchestrator.close()


def test_sanitized_output_reaches_final_decision_on_allow():
    """When sanitize() resolves cleanly AND the final decision is ALLOW,
    the redacted tool-output text must reach SecurityDecision.sanitized_output.
    """
    from security.plugins.guards.output_guard import OutputGuard

    # First WARN (low risk) just to get mode to STRICT; Output Guard's own
    # WARN (0.95) + the sanitize retry (0.0) combine via noisy-OR to 0.96 —
    # thresholds set so that stays under both block_threshold and
    # strict_threshold, letting the run end in ALLOW.
    policy = PolicyConfig(policy_version="v0.1.0-p0-baseline", strict_threshold=0.97, block_threshold=0.999)
    orchestrator, _enf, _ev, manager = _build(policy=policy)
    manager.register_guard(_FixedGuard("context_guard", Stage.CONTEXT, Decision.WARN, 0.2))
    manager.register_guard(OutputGuard())

    class _LeakyEnforcement:
        def enforce(self, decision):
            from enums import ExecutionState
            from schemas import ExecutionResult
            return ExecutionResult(
                run_id=decision.run_id, trace_id=decision.trace_id,
                execution_state=ExecutionState.EXECUTED, executed=True, tool_name="read_file",
                output={"content": "here you go: API_KEY=sk-leak123"}, latency_ms=1.0,
            )

    orchestrator.enforcement = _LeakyEnforcement()
    observation = mock_runtime_observation(tool_candidate={"tool_name": "read_file"})

    decision = orchestrator.evaluate(observation)

    assert decision.decision == Decision.ALLOW
    assert decision.sanitized_output == "here you go: [REDACTED]"


def test_sanitized_output_withheld_when_final_decision_is_not_allow():
    """Same setup as above, but with strict_threshold lowered so the final
    decision ends up WARN instead of ALLOW — sanitize() still succeeds
    internally, but sanitized_output must NOT appear on the returned
    decision, per the agreed Runtime output-usage rule.
    """
    from security.plugins.guards.output_guard import OutputGuard

    policy = PolicyConfig(policy_version="v0.1.0-p0-baseline", strict_threshold=0.50, block_threshold=0.999)
    orchestrator, _enf, _ev, manager = _build(policy=policy)
    manager.register_guard(_FixedGuard("context_guard", Stage.CONTEXT, Decision.WARN, 0.2))
    manager.register_guard(OutputGuard())

    class _LeakyEnforcement:
        def enforce(self, decision):
            from enums import ExecutionState
            from schemas import ExecutionResult
            return ExecutionResult(
                run_id=decision.run_id, trace_id=decision.trace_id,
                execution_state=ExecutionState.EXECUTED, executed=True, tool_name="read_file",
                output={"content": "here you go: API_KEY=sk-leak123"}, latency_ms=1.0,
            )

    orchestrator.enforcement = _LeakyEnforcement()
    observation = mock_runtime_observation(tool_candidate={"tool_name": "read_file"})

    decision = orchestrator.evaluate(observation)

    assert decision.decision == Decision.WARN
    assert decision.sanitized_output is None
