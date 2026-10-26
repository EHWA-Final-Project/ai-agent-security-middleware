"""Guard and Security Core latency recording."""

import time

from enums import Decision, ExecutionState, GuardExecutionStatus, Stage
from fixtures import mock_runtime_observation
from schemas import ExecutionResult

from security.orchestrator.orchestrator import SecurityOrchestrator
from security.plugins.interface import GuardPlugin
from security.policy.conditions import build_plugin_manager, load_condition

_MAIL = {"message_id": "m1", "accepted": True, "delivery": "mock"}


class _Enforcement:
    def __init__(self, delay: float = 0.0) -> None:
        self._delay = delay

    def enforce(self, decision):
        time.sleep(self._delay)
        executed = decision.decision == Decision.ALLOW
        return ExecutionResult(
            run_id=decision.run_id, trace_id=decision.trace_id, tool_name="send_email",
            execution_state=ExecutionState.EXECUTED if executed else ExecutionState.BLOCKED,
            executed=executed, output=_MAIL if executed else None, latency_ms=1.0,
        )


class _Evidence:
    def __init__(self, delay: float = 0.0) -> None:
        self._delay = delay
        self.results = []
        self.decisions = []

    def record_result(self, result):
        time.sleep(self._delay)
        self.results.append(result)

    def record_decision(self, decision):
        time.sleep(self._delay)
        self.decisions.append(decision)


class _SlowGuard(GuardPlugin):
    name = "slow_guard"
    stage = Stage.INPUT

    def inspect(self, observation, context):
        time.sleep(0.4)
        raise AssertionError("timeout should fire first")


class _CrashingGuard(GuardPlugin):
    name = "crashing_guard"
    stage = Stage.INPUT

    def inspect(self, observation, context):
        raise RuntimeError("simulated guard bug")


def _observation():
    return mock_runtime_observation(
        user_input="Send this summary to my manager.",
        tool_candidate={"tool_call_id": "call-1", "tool_name": "send_email", "tool_arguments": {}},
    )


def _orchestrator(condition_name="C", *, enforcement=None, evidence=None, extra_guards=(), timeout=2.0):
    condition = load_condition(condition_name)
    manager = build_plugin_manager(condition)
    for guard in extra_guards:
        manager.register_guard(guard)
    evidence = evidence or _Evidence()
    orchestrator = SecurityOrchestrator(
        manager, condition.policy, enforcement or _Enforcement(), evidence,
        guard_timeout_sec=timeout,
    )
    return orchestrator, evidence


def test_guard_wall_time_is_recorded_for_every_guard_call_and_covers_reported_latency():
    orchestrator, evidence = _orchestrator("C")
    try:
        orchestrator.evaluate(_observation())
    finally:
        orchestrator.close()
    timing = orchestrator.last_timing

    assert [name for name, _ in timing.guard_wall_ms] == [r.guard_name for r in evidence.results]
    assert {name for name, _ in timing.guard_wall_ms} == {
        "input_guard", "context_guard", "tool_guard", "output_guard",
    }
    # The Guard's own timer sits inside the Orchestrator's wall-clock timer.
    for (_, wall), result in zip(timing.guard_wall_ms, evidence.results, strict=True):
        assert wall >= result.latency_ms
    assert timing.guard_wall_total_ms >= sum(r.latency_ms for r in evidence.results)


def test_no_guard_condition_records_no_guard_time():
    orchestrator, evidence = _orchestrator("A")
    try:
        decision = orchestrator.evaluate(_observation())
    finally:
        orchestrator.close()
    timing = orchestrator.last_timing

    assert decision.decision == Decision.ALLOW
    assert evidence.results == []
    assert timing.guard_wall_ms == []
    assert timing.guard_wall_total_ms == 0.0
    assert timing.evaluate_ms > 0


def test_tool_execution_time_is_not_counted_as_security_core_time():
    orchestrator, _ = _orchestrator("C", enforcement=_Enforcement(delay=0.05))
    try:
        orchestrator.evaluate(_observation())
    finally:
        orchestrator.close()
    timing = orchestrator.last_timing

    assert timing.enforcement_ms >= 45
    assert timing.evaluate_ms >= timing.enforcement_ms
    assert timing.security_core_ms < timing.enforcement_ms


def test_evidence_write_time_is_not_counted_as_security_core_time():
    orchestrator, evidence = _orchestrator("C", evidence=_Evidence(delay=0.02))
    try:
        orchestrator.evaluate(_observation())
    finally:
        orchestrator.close()
    timing = orchestrator.last_timing

    records = len(evidence.results) + len(evidence.decisions)
    assert records >= 2
    assert timing.evidence_ms >= 0.8 * records * 20
    assert timing.security_core_ms < timing.evidence_ms


def test_components_never_exceed_the_whole_call():
    orchestrator, _ = _orchestrator("B", enforcement=_Enforcement(delay=0.01), evidence=_Evidence(delay=0.005))
    try:
        orchestrator.evaluate(_observation())
    finally:
        orchestrator.close()
    timing = orchestrator.last_timing

    assert timing.enforcement_ms + timing.evidence_ms <= timing.evaluate_ms
    assert 0 <= timing.security_core_ms <= timing.evaluate_ms
    assert timing.guard_wall_total_ms <= timing.evaluate_ms


def test_timing_is_reset_on_every_evaluate_call():
    orchestrator, _ = _orchestrator("C")
    try:
        orchestrator.evaluate(_observation())
        first = orchestrator.last_timing
        orchestrator.evaluate(_observation())
        second = orchestrator.last_timing
    finally:
        orchestrator.close()

    assert second is not first
    assert len(second.guard_wall_ms) == len(first.guard_wall_ms)


def test_timed_out_guard_still_reports_latency_and_wall_time():
    orchestrator, evidence = _orchestrator("B", extra_guards=[_SlowGuard()], timeout=0.1)
    try:
        orchestrator.evaluate(_observation())
    finally:
        orchestrator.close()

    slow = next(r for r in evidence.results if r.guard_name == "slow_guard")
    wall = dict(orchestrator.last_timing.guard_wall_ms)["slow_guard"]
    assert slow.execution_status == GuardExecutionStatus.TIMEOUT
    assert slow.latency_ms >= 90
    assert wall >= 90


def test_crashed_guard_still_reports_latency_and_wall_time():
    orchestrator, evidence = _orchestrator("B", extra_guards=[_CrashingGuard()])
    try:
        orchestrator.evaluate(_observation())
    finally:
        orchestrator.close()

    crashed = next(r for r in evidence.results if r.guard_name == "crashing_guard")
    assert crashed.execution_status == GuardExecutionStatus.ERROR
    assert crashed.latency_ms >= 0
    assert "crashing_guard" in dict(orchestrator.last_timing.guard_wall_ms)
