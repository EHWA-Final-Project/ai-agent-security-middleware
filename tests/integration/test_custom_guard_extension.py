from enums import Decision, Stage
from fixtures import mock_runtime_observation

from examples.custom_guard import CustomKeywordGuard
from security.orchestrator.orchestrator import SecurityOrchestrator
from security.plugins.manager import PluginManager
from security.policy.config import PolicyConfig


def test_custom_guard_registration():
    manager = PluginManager()

    manager.register_guard(CustomKeywordGuard())

    guards = manager.guards_for_stage(Stage.INPUT)

    assert len(guards) == 1
    assert guards[0].name == "custom_keyword_guard"


def test_custom_guard_disabled():
    manager = PluginManager()

    manager.register_guard(CustomKeywordGuard(), enabled=False)

    guards = manager.guards_for_stage(Stage.INPUT)

    assert guards == []


def test_custom_guard_enable_after_registration():
    manager = PluginManager()

    manager.register_guard(CustomKeywordGuard(), enabled=False)

    assert manager.guards_for_stage(Stage.INPUT) == []

    manager.registry.set_enabled("custom_keyword_guard", True)

    guards = manager.guards_for_stage(Stage.INPUT)

    assert len(guards) == 1
    assert guards[0].name == "custom_keyword_guard"

class RecordingEnforcement:
    def __init__(self):
        self.calls = []

    def enforce(self, decision):
        self.calls.append(decision)


class RecordingEvidence:
    def __init__(self):
        self.results = []
        self.decisions = []

    def record_result(self, result):
        self.results.append(result)

    def record_decision(self, decision):
        self.decisions.append(decision)


def build_orchestrator(enabled=True):
    manager = PluginManager()
    manager.register_guard(CustomKeywordGuard(), enabled=enabled)

    enforcement = RecordingEnforcement()
    evidence = RecordingEvidence()

    orchestrator = SecurityOrchestrator(
        plugin_manager=manager,
        policy_config=PolicyConfig(
            policy_version="custom-guard-test",
            strict_threshold=0.5,
            block_threshold=0.75,
        ),
        enforcement=enforcement,
        evidence_sink=evidence,
    )

    return orchestrator, manager, enforcement, evidence


def test_custom_guard_executes_through_orchestrator():
    orchestrator, _, enforcement, evidence = build_orchestrator()

    observation = mock_runtime_observation(
        user_input="This contains restricted-demo-token."
    )

    decision = orchestrator.evaluate(observation)

    assert decision.decision == Decision.BLOCK

    assert len(evidence.results) == 1
    assert evidence.results[0].guard_name == "custom_keyword_guard"
    assert evidence.results[0].decision == Decision.WARN
    assert evidence.results[0].risk_score == 0.8

    assert decision.cumulative_risk_score >= 0.75
    assert enforcement.calls == []


def test_custom_guard_allows_normal_input():
    orchestrator, _, enforcement, evidence = build_orchestrator()

    observation = mock_runtime_observation(
        user_input="Summarize this document."
    )

    decision = orchestrator.evaluate(observation)

    assert decision.decision == Decision.ALLOW

    assert len(evidence.results) == 1
    assert evidence.results[0].guard_name == "custom_keyword_guard"
    assert evidence.results[0].decision == Decision.ALLOW

    assert enforcement.calls == []


def test_disabled_custom_guard_not_executed_by_orchestrator():
    orchestrator, _, enforcement, evidence = build_orchestrator(
        enabled=False
    )

    observation = mock_runtime_observation(
        user_input="This contains restricted-demo-token."
    )

    decision = orchestrator.evaluate(observation)

    assert decision.decision == Decision.ALLOW
    assert evidence.results == []
    assert enforcement.calls == []
