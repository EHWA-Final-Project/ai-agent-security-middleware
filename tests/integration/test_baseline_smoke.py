"""9/26 Baseline Integration Smoke — Fatin's scope only.

Covers:
  - Common ID (run_id/trace_id) generation + propagation format
  - Sample Guard -> SecurityResult
  - (re-confirmed for 9/27 M1 Gate) Sample Guard called through Plugin Registry
"""

from enums import Decision, GuardExecutionStatus, Stage
from fixtures import mock_runtime_observation
from ids import new_run_id, new_session_id, new_trace_id

from security.plugins.guards.input_guard import InputGuard
from security.plugins.manager import PluginManager


def test_common_id_format_is_consistent():
    """Common ID 생성·전파 형식 확인: IDs follow the defined "<kind>-<hex12>"
    shape and are unique across calls.
    """
    run_id = new_run_id()
    trace_id = new_trace_id()
    session_id = new_session_id()

    assert run_id.startswith("run-") and len(run_id) == len("run-") + 12
    assert trace_id.startswith("trace-") and len(trace_id) == len("trace-") + 12
    assert session_id.startswith("session-") and len(session_id) == len("session-") + 12

    assert new_run_id() != run_id, "IDs must be unique across calls"


def test_common_id_propagates_unchanged_through_guard_execution():
    """Common ID 전파 확인: the run_id/trace_id set on the RuntimeObservation
    must come back byte-for-byte identical on the SecurityResult — no
    guard is allowed to generate its own ID or silently drop it.
    """
    run_id = new_run_id()
    trace_id = new_trace_id()
    observation = mock_runtime_observation(run_id=run_id, trace_id=trace_id)

    guard = InputGuard()
    manager = PluginManager()
    manager.register_guard(guard)

    from schemas.security import SecurityContext

    context = SecurityContext(
        run_id=run_id,
        trace_id=trace_id,
        current_stage=Stage.INPUT,
        policy_version="v0.1.0-p0-baseline",
    )
    result = guard.inspect(observation, context)

    assert result.run_id == run_id
    assert result.trace_id == trace_id


def test_sample_guard_returns_valid_security_result():
    """Sample Guard -> SecurityResult 반환 확인."""
    observation = mock_runtime_observation(user_input="Summarize this document for me.")
    guard = InputGuard()

    from schemas.security import SecurityContext

    context = SecurityContext(
        run_id=observation.run_id,
        trace_id=observation.trace_id,
        current_stage=Stage.INPUT,
        policy_version="v0.1.0-p0-baseline",
    )
    result = guard.inspect(observation, context)

    assert result.execution_status == GuardExecutionStatus.SUCCESS
    assert result.decision in (Decision.ALLOW, Decision.WARN, Decision.BLOCK)
    assert result.guard_name == "input_guard"
    assert result.stage == Stage.INPUT
    assert isinstance(result.latency_ms, float)


def test_sample_guard_is_invoked_through_plugin_registry_not_direct_import():
    """9/27 M1 Gate: 'Sample Guard가 Plugin Registry를 통해 호출됨' — proves
    dispatch goes through PluginManager.guards_for_stage(), not a direct
    call to InputGuard() from calling code.
    """
    manager = PluginManager()
    manager.register_guard(InputGuard())

    guards = manager.guards_for_stage(Stage.INPUT)
    assert len(guards) == 1

    observation = mock_runtime_observation()
    from schemas.security import SecurityContext

    context = SecurityContext(
        run_id=observation.run_id,
        trace_id=observation.trace_id,
        current_stage=Stage.INPUT,
        policy_version="v0.1.0-p0-baseline",
    )
    # Guard obtained purely via registry lookup, not `InputGuard()` directly.
    result = guards[0].inspect(observation, context)
    assert result.execution_status == GuardExecutionStatus.SUCCESS
