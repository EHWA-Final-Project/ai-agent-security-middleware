"""사용자 정의 Guard 계약 테스트 (FT-07).

새 Guard를 등록만 하면 Orchestrator 코드 변경 없이 동작하는지 확인한다.
- 등록, 단계별 조회, 중복 이름 거부, 비활성화
- 점수가 B(독립)와 C(누적)에서 기대대로 판정에 반영됨
- 실행 실패(예외)의 격리: Input 단계는 계속 진행, Tool 단계는 실행 전 차단(fail-closed)
"""

import sys
from pathlib import Path

import pytest
from enums import Decision, ExecutionState, GuardExecutionStatus, Stage
from fixtures import mock_runtime_observation
from schemas import ExecutionResult

from security.orchestrator.orchestrator import SecurityOrchestrator
from security.plugins.interface import GuardPlugin
from security.policy.conditions import build_plugin_manager, load_condition

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "examples"))
from custom_guard import BlockedTermGuard

_MAIL = {"message_id": "m1", "accepted": True, "delivery": "mock"}


class _Enforcement:
    def __init__(self, tool_name):
        self._tool_name, self.tool_ran = tool_name, False

    def enforce(self, decision):
        self.tool_ran = decision.decision == Decision.ALLOW
        return ExecutionResult(
            run_id=decision.run_id, trace_id=decision.trace_id, tool_name=self._tool_name,
            execution_state=ExecutionState.EXECUTED if self.tool_ran else ExecutionState.BLOCKED,
            executed=self.tool_ran, output=_MAIL if self.tool_ran else None, latency_ms=1.0,
        )


class _Evidence:
    def __init__(self):
        self.results, self.decisions = [], []

    def record_result(self, result):
        self.results.append(result)

    def record_decision(self, decision):
        self.decisions.append(decision)


class _ExplodingGuard(GuardPlugin):
    name = "exploding_guard"

    def __init__(self, stage):
        self.stage = stage

    def inspect(self, observation, context):
        raise RuntimeError("boom")


def _run(condition_name, guards, user_input, tool_name="send_email"):
    condition = load_condition(condition_name)
    manager = build_plugin_manager(condition)
    for guard in guards:
        manager.register_guard(guard)
    enforcement, evidence = _Enforcement(tool_name), _Evidence()
    orchestrator = SecurityOrchestrator(manager, condition.policy, enforcement, evidence)
    observation = mock_runtime_observation(
        user_input=user_input,
        tool_candidate={"tool_call_id": "c1", "tool_name": tool_name, "tool_arguments": {"to": ["a@b.c"]}},
    )
    decision = orchestrator.evaluate(observation)
    orchestrator.close()
    return decision, enforcement, evidence


def test_guard_registers_by_stage_without_orchestrator_changes():
    manager = build_plugin_manager(load_condition("C"))
    custom = BlockedTermGuard({"project-x"})
    manager.register_guard(custom)

    assert custom in manager.guards_for_stage(Stage.INPUT)
    assert custom not in manager.guards_for_stage(Stage.TOOL)


def test_duplicate_name_is_rejected_and_disabled_guard_is_skipped():
    manager = build_plugin_manager(load_condition("C"))
    manager.register_guard(BlockedTermGuard({"x"}))
    with pytest.raises(ValueError):
        manager.register_guard(BlockedTermGuard({"y"}))

    manager.registry.set_enabled("blocked_term_guard", False)
    assert all(g.name != "blocked_term_guard" for g in manager.guards_for_stage(Stage.INPUT))


@pytest.mark.parametrize("name", ["B", "C"])
def test_high_risk_custom_guard_blocks_before_the_tool_runs(name):
    decision, enforcement, evidence = _run(name, [BlockedTermGuard({"project-x"}, risk=0.9)], "Tell me about Project-X")

    assert decision.decision == Decision.BLOCK
    assert enforcement.tool_ran is False
    assert any(r.guard_name == "blocked_term_guard" and r.risk_score == 0.9 for r in evidence.results)


@pytest.mark.parametrize("name", ["A", "B", "C"])
def test_input_without_a_match_is_allowed(name):
    decision, enforcement, _ = _run(name, [BlockedTermGuard({"project-x"})], "Summarize the meeting notes.", "read_file")

    assert decision.decision == Decision.ALLOW
    assert enforcement.tool_ran is True


def test_custom_score_accumulates_in_c_but_not_in_b():
    # 사용자 정의 Guard 0.6 + Tool Guard(send_email) 0.6 -> noisy-OR 0.84 >= 0.80
    guard = BlockedTermGuard({"project-x"}, risk=0.6)

    c_decision, c_enf, _ = _run("C", [guard], "Tell me about Project-X")
    b_decision, _, _ = _run("B", [BlockedTermGuard({"project-x"}, risk=0.6)], "Tell me about Project-X")

    assert c_decision.decision == Decision.BLOCK and c_enf.tool_ran is False
    assert b_decision.decision != Decision.BLOCK  # B는 점수를 합치지 않는다


def test_failing_input_guard_does_not_stop_the_run():
    decision, enforcement, evidence = _run("C", [_ExplodingGuard(Stage.INPUT)], "Summarize the meeting notes.", "read_file")

    assert decision.decision == Decision.ALLOW and enforcement.tool_ran is True
    assert any(r.execution_status == GuardExecutionStatus.ERROR for r in evidence.results)


def test_failing_tool_guard_fails_closed_before_the_tool_runs():
    decision, enforcement, _ = _run("C", [_ExplodingGuard(Stage.TOOL)], "Summarize the meeting notes.", "read_file")

    assert decision.decision == Decision.BLOCK and enforcement.tool_ran is False
