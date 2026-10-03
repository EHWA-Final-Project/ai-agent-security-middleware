from enums import Decision, GuardExecutionStatus, Stage
from schemas import SecurityResult

from security.plugins.interface import GuardPlugin
from security.plugins.registry import PluginRegistry


class _DummyGuard(GuardPlugin):
    name = "dummy_guard"
    stage = Stage.INPUT

    def inspect(self, observation, context) -> SecurityResult:
        return SecurityResult(
            run_id=observation.run_id,
            trace_id=observation.trace_id,
            stage=self.stage,
            guard_name=self.name,
            execution_status=GuardExecutionStatus.SUCCESS,
            risk_score=0.0,
            decision=Decision.ALLOW,
            latency_ms=0.1,
        )


class _AnotherDummyGuard(_DummyGuard):
    name = "another_dummy_guard"


def test_register_and_retrieve_guard_by_stage():
    registry = PluginRegistry()
    registry.register(_DummyGuard())

    guards = registry.guards_for_stage(Stage.INPUT)
    assert len(guards) == 1
    assert guards[0].name == "dummy_guard"


def test_add_new_guard_without_touching_orchestrator_code():
    """Proves a guard can be added purely via registration — the P0 Done
    criterion: 'Guard 추가 시 Orchestrator 수정 없이 Registry 등록으로 실행 가능'."""
    registry = PluginRegistry()
    registry.register(_DummyGuard())
    registry.register(_AnotherDummyGuard())

    guards = registry.guards_for_stage(Stage.INPUT)
    assert {g.name for g in guards} == {"dummy_guard", "another_dummy_guard"}


def test_disabled_guard_excluded_from_stage_lookup():
    registry = PluginRegistry()
    registry.register(_DummyGuard())
    registry.set_enabled("dummy_guard", False)

    assert registry.guards_for_stage(Stage.INPUT) == []


def test_priority_controls_order():
    registry = PluginRegistry()
    registry.register(_DummyGuard(), priority=50)
    registry.register(_AnotherDummyGuard(), priority=10)

    guards = registry.guards_for_stage(Stage.INPUT)
    assert [g.name for g in guards] == ["another_dummy_guard", "dummy_guard"]


def test_duplicate_registration_raises():
    registry = PluginRegistry()
    registry.register(_DummyGuard())
    try:
        registry.register(_DummyGuard())
        assert False, "expected ValueError on duplicate registration"
    except ValueError:
        pass
