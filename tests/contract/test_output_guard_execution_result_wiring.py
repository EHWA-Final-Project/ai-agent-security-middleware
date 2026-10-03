from enums import Decision, ExecutionState, GuardExecutionStatus
from fixtures import mock_runtime_observation
from schemas import ExecutionResult, SecurityDecision, SecurityResult

from security.orchestrator.orchestrator import SecurityOrchestrator
from security.plugins.guards.input_guard import InputGuard
from security.plugins.guards.output_guard import OutputGuard
from security.plugins.manager import PluginManager
from security.policy.config import PolicyConfig


class _RecordingEvidenceSink:
    def __init__(self) -> None:
        self.results: list[SecurityResult] = []
        self.decisions: list[SecurityDecision] = []

    def record_result(self, result: SecurityResult) -> None:
        self.results.append(result)

    def record_decision(self, decision: SecurityDecision) -> None:
        self.decisions.append(decision)


class _LeakyEnforcement:
    """Stand-in for 지원's Enforcement whose tool happens to leak a secret
    in its output — proves the ExecutionResult it returns actually reaches
    Output Guard through SecurityContext, not just gets discarded.
    """

    def __init__(self) -> None:
        self.calls: list = []

    def enforce(self, decision):
        self.calls.append(decision)
        if decision.decision != Decision.ALLOW:
            return ExecutionResult(
                run_id=decision.run_id, trace_id=decision.trace_id,
                execution_state=ExecutionState.BLOCKED, executed=False,
                output=None, latency_ms=1.0,
            )
        return ExecutionResult(
            run_id=decision.run_id, trace_id=decision.trace_id,
            tool_name="read_file", execution_state=ExecutionState.EXECUTED,
            executed=True, output="dump: API_KEY=sk-leaked123", latency_ms=5.0,
        )


def test_execution_result_from_enforcement_reaches_output_guard():
    manager = PluginManager()
    manager.register_guard(InputGuard())
    manager.register_guard(OutputGuard())

    policy = PolicyConfig(policy_version="v0.1.0-p0-baseline", strict_threshold=0.50, block_threshold=0.90)
    enforcement = _LeakyEnforcement()
    evidence = _RecordingEvidenceSink()
    orchestrator = SecurityOrchestrator(
        plugin_manager=manager, policy_config=policy, enforcement=enforcement, evidence_sink=evidence,
    )

    observation = mock_runtime_observation(
        user_input="Read the config file for me.",
        tool_candidate={"tool_name": "read_file", "args": {"path": "config.txt"}},
    )
    decision = orchestrator.evaluate(observation)

    # Input stage was clean -> Enforcement ran the tool -> tool leaked a
    # secret -> Output Guard (reading context.execution_result) must catch
    # it and the final decision must reflect that, not silently ALLOW.
    output_results = [r for r in evidence.results if r.guard_name == "output_guard"]
    assert len(output_results) == 1
    assert output_results[0].decision == Decision.WARN
    assert output_results[0].execution_status == GuardExecutionStatus.SUCCESS
    assert "output_guard.secret_leakage" in output_results[0].rule_ids

    assert decision.decision in (Decision.WARN, Decision.BLOCK)
    # Enforcement was called exactly once (at Tool Decision), not again
    # for the Output-stage finding.
    assert len(enforcement.calls) == 1
