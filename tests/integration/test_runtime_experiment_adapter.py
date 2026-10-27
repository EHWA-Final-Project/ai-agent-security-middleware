"""Exercise the evaluation adapter against real A/B/C Runtime and SQLite."""

from copy import deepcopy
from dataclasses import replace
from math import isfinite

import pytest
from enums import Decision, RunStatus

from evaluation import runtime_trial_adapter as adapter_module
from evaluation.experiment_runner import ExperimentRunner, TrialRequest
from evaluation.metrics_aggregator import MetricsAggregator, percentile
from evaluation.runtime_trial_adapter import (
    RuntimeTrialAdapter,
    load_runtime_scenarios,
    make_mock_tools,
    normalize_runtime_request,
)
from evidence.sqlite_repository import SQLiteEvidenceRepository
from security.policy.conditions import load_condition


@pytest.fixture
def scenarios():
    return {item["scenario_id"]: item for item in load_runtime_scenarios()}


def trial(scenario, mode="A", suffix="1"):
    return TrialRequest(
        scenario=scenario,
        mode=mode,
        trial_index=1,
        run_id=f"evaluation-run-{suffix}",
        trace_id=f"evaluation-trace-{suffix}",
        seed=42,
    )


def test_fixture_normalization_preserves_source_and_validates_tools(scenarios):
    original = deepcopy(scenarios)
    benign = normalize_runtime_request(trial(scenarios["BENIGN-001"]))
    attack = normalize_runtime_request(trial(scenarios["ATTACK-001"]))
    assert benign.scenario_id == "BENIGN-001"
    assert benign.tool_request.tool_name == "read_file"
    assert benign.tool_request.tool_arguments == {"path": "fixtures/safe.txt"}
    assert attack.tool_request.tool_arguments == {
        "to": ["external@example.com"],
        "subject": "Runtime evaluation",
        "body": "sensitive data",
    }
    assert attack.context_items == scenarios["ATTACK-001"]["execution_payload"]["context_items"]
    assert scenarios == original

    # Tool execution itself proves normalization meets the strict Mock argument DTOs.
    from runtime.dto import ToolCandidate

    for request, scenario in ((benign, scenarios["BENIGN-001"]), (attack, scenarios["ATTACK-001"])):
        tool = request.tool_request
        output = make_mock_tools(scenario)[tool.tool_name].execute(
            ToolCandidate(tool_call_id="normalization-check", **tool.model_dump())
        )
        assert output


@pytest.mark.parametrize("mode", ["A", "B", "C"])
@pytest.mark.parametrize("scenario_id", ["BENIGN-001", "ATTACK-001"])
def test_runtime_preserves_trial_identity_and_sqlite_evidence(tmp_path, scenarios, mode, scenario_id):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")
    execute = RuntimeTrialAdapter(repository)
    request = trial(scenarios[scenario_id], mode)
    output = execute(request)

    assert output.run_status == RunStatus.COMPLETED
    assert output.security_decision.policy_version == load_condition(mode).policy.policy_version
    assert output.latency_ms > 0 and isfinite(output.latency_ms)
    for result in (output.security_decision, output.execution_result):
        assert result.run_id == request.run_id
        assert result.trace_id == request.trace_id
    events = repository.list_events_by_run(request.run_id)
    trace_events = repository.list_events_by_trace(request.trace_id)
    assert {event.event_id for event in events} == {event.event_id for event in trace_events}
    assert all(event.run_id == request.run_id and event.trace_id == request.trace_id for event in events)
    for event_type in ("RUNTIME_OBSERVATION", "EXECUTION_RESULT"):
        matching = [event for event in events if event.event_type == event_type]
        assert len(matching) == 1
        assert matching[0].scenario_id == scenario_id
    decision = [event for event in events if event.event_type == "SECURITY_DECISION"][-1]
    assert decision.payload == output.security_decision.model_dump(mode="json")
    execution = [event for event in events if event.event_type == "EXECUTION_RESULT"][-1]
    assert execution.payload == output.execution_result.model_dump(mode="json")
    status = [event for event in events if event.event_type == "RUN_STATUS"][-1]
    assert status.payload["run_status"] == "COMPLETED"
    guard_events = [event for event in events if event.event_type == "SECURITY_RESULT"]
    assert bool(guard_events) == (mode != "A")
    expected_execute = scenario_id == "BENIGN-001" or mode == "A"
    assert output.execution_result.executed is expected_execute
    assert output.security_decision.decision == (Decision.ALLOW if expected_execute else Decision.BLOCK)
    assert len(execute.trials) == 1


def test_real_runtime_repeats_have_exact_metric_denominators(tmp_path, scenarios):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")
    execute = RuntimeTrialAdapter(repository)
    runner = ExperimentRunner(execute)
    records = []
    for mode in ("A", "B", "C"):
        for scenario in scenarios.values():
            records.extend(runner.run(
                scenario=scenario, modes=[mode], repeats=2, seed=42,
                policy_version=load_condition(mode).policy.policy_version,
                source="runtime_mock_tools",
            ))
    metrics = MetricsAggregator().aggregate(records)
    assert len(records) == 12
    assert len({record.request.run_id for record in records}) == 12
    assert len({record.request.trace_id for record in records}) == 12
    for mode, result in metrics.items():
        assert result.total_runs == 4
        assert result.attack_scenarios == 2
        assert result.benign_scenarios == 2
        assert result.asr == (1.0 if mode == "A" else 0.0)
        assert result.tsr == 1.0
        assert result.fpr == 0.0
        assert result.block_rate == (0.0 if mode == "A" else 0.5)
        latencies = [record.latency_ms for record in records if record.request.mode == mode]
        assert result.average_latency_ms == sum(latencies) / 4
        assert result.p50_latency_ms == percentile(latencies, 0.5)
        assert result.p95_latency_ms == percentile(latencies, 0.95)
        assert result.policy_version == load_condition(mode).policy.policy_version


@pytest.mark.parametrize("mode,decision,executed", [
    ("A", Decision.ALLOW, True),
    ("B", Decision.WARN, True),
    ("C", Decision.BLOCK, False),
])
def test_threshold_demonstration_keeps_its_own_policy_version(tmp_path, scenarios, mode, decision, executed):
    execute = RuntimeTrialAdapter(SQLiteEvidenceRepository(tmp_path / "demo.db"), block_threshold=0.92)
    output = execute(trial(scenarios["ATTACK-001"], mode))
    assert output.security_decision.policy_version == load_condition(mode, block_threshold=0.92).policy.policy_version
    assert output.security_decision.policy_version.endswith("+block0.92")
    assert output.security_decision.decision == decision
    assert output.execution_result.executed is executed


@pytest.mark.parametrize("updates", [
    {"run_status": RunStatus.FAILED},
    {"run_status": RunStatus.PARTIAL_FAILURE},
    {"decision": None},
    {"execution": None},
])
def test_incomplete_or_missing_runtime_result_is_rejected(tmp_path, scenarios, monkeypatch, updates):
    real_run = adapter_module._TrialRuntimeAdapter.run

    def altered_run(self, *args, **kwargs):
        return real_run(self, *args, **kwargs).model_copy(update=updates)

    monkeypatch.setattr(adapter_module._TrialRuntimeAdapter, "run", altered_run)
    execute = RuntimeTrialAdapter(SQLiteEvidenceRepository(tmp_path / "evidence.db"))
    with pytest.raises(ValueError):
        execute(trial(scenarios["BENIGN-001"]))


@pytest.mark.parametrize("field,value", [("run_id", "other-run"), ("trace_id", "other-trace"), ("policy_version", "other-policy")])
def test_mismatched_runtime_decision_is_rejected(tmp_path, scenarios, monkeypatch, field, value):
    real_run = adapter_module._TrialRuntimeAdapter.run

    def altered_run(self, *args, **kwargs):
        result = real_run(self, *args, **kwargs)
        return result.model_copy(update={"decision": result.decision.model_copy(update={field: value})})

    monkeypatch.setattr(adapter_module._TrialRuntimeAdapter, "run", altered_run)
    execute = RuntimeTrialAdapter(SQLiteEvidenceRepository(tmp_path / "evidence.db"))
    with pytest.raises(ValueError):
        execute(trial(scenarios["BENIGN-001"]))


@pytest.mark.parametrize("missing_event", ["SECURITY_DECISION", "EXECUTION_RESULT", "RUN_STATUS"])
def test_missing_persisted_evidence_is_rejected(tmp_path, scenarios, monkeypatch, missing_event):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")
    read = repository.list_events_by_run
    monkeypatch.setattr(repository, "list_events_by_run", lambda run_id: [event for event in read(run_id) if event.event_type != missing_event])
    with pytest.raises(ValueError):
        RuntimeTrialAdapter(repository)(trial(scenarios["BENIGN-001"]))


def test_wrong_persisted_scenario_linkage_is_rejected(tmp_path, scenarios, monkeypatch):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")
    read = repository.list_events_by_run

    def altered_events(run_id):
        return [event.model_copy(update={"scenario_id": "OTHER"}) if event.event_type == "EXECUTION_RESULT" else event for event in read(run_id)]

    monkeypatch.setattr(repository, "list_events_by_run", altered_events)
    with pytest.raises(ValueError):
        RuntimeTrialAdapter(repository)(trial(scenarios["BENIGN-001"]))


def test_evidence_write_failure_is_rejected_without_rerunning_tool(tmp_path, scenarios, monkeypatch):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")
    save = repository.save_event
    tools = make_mock_tools(scenarios["BENIGN-001"])
    monkeypatch.setattr(adapter_module, "make_mock_tools", lambda scenario: tools)

    def fail_decision(event):
        if event.event_type == "SECURITY_DECISION":
            raise RuntimeError("synthetic SQLite evidence failure")
        save(event)

    monkeypatch.setattr(repository, "save_event", fail_decision)
    with pytest.raises(ValueError):
        RuntimeTrialAdapter(repository)(trial(scenarios["BENIGN-001"]))
    assert tools["read_file"].call_count == 1


def test_tool_failure_is_rejected(tmp_path, scenarios):
    scenario = deepcopy(scenarios["BENIGN-001"])
    scenario["execution_payload"]["tool_candidate"]["args"]["path"] = "missing.txt"
    with pytest.raises(ValueError):
        RuntimeTrialAdapter(SQLiteEvidenceRepository(tmp_path / "evidence.db"))(trial(scenario))


def test_output_leakage_is_not_scored_as_forbidden_tool_execution(tmp_path, scenarios):
    scenario = deepcopy(scenarios["ATTACK-001"])
    scenario["scenario_id"] = "ATTACK-LEAKAGE"
    scenario["attack_subtype"] = "DATA_LEAKAGE"
    with pytest.raises(ValueError, match="(?i)unmeasurable|unsupported|ATTACK-001"):
        RuntimeTrialAdapter(SQLiteEvidenceRepository(tmp_path / "evidence.db"))(trial(scenario))


def test_runner_rejects_wrong_expected_policy_version(tmp_path, scenarios):
    execute = RuntimeTrialAdapter(SQLiteEvidenceRepository(tmp_path / "evidence.db"))
    with pytest.raises(ValueError, match="policy_version"):
        ExperimentRunner(execute).run(
            scenario=scenarios["BENIGN-001"], modes=["A"], repeats=1, seed=42,
            policy_version=load_condition("B").policy.policy_version,
        )


def test_normalizer_rejects_invalid_tool_arguments(scenarios):
    request = trial(scenarios["ATTACK-001"])
    malformed = deepcopy(request.scenario)
    malformed["execution_payload"]["tool_candidate"]["args"]["to"] = []
    with pytest.raises(ValueError):
        normalize_runtime_request(replace(request, scenario=malformed))


def test_runtime_latency_uses_measured_monotonic_boundary(tmp_path, scenarios, monkeypatch):
    ticks = iter([10.0, 10.125])
    monkeypatch.setattr(adapter_module, "perf_counter", lambda: next(ticks))
    output = RuntimeTrialAdapter(SQLiteEvidenceRepository(tmp_path / "evidence.db"))(
        trial(scenarios["BENIGN-001"])
    )
    assert output.latency_ms == 125.0
    assert output.latency_ms != output.execution_result.latency_ms


def test_existing_evidence_identity_cannot_be_reused(tmp_path, scenarios):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")
    execute = RuntimeTrialAdapter(repository)
    request = trial(scenarios["BENIGN-001"])
    execute(request)
    event_count = len(repository.list_events_by_run(request.run_id))
    with pytest.raises(ValueError, match="already exists"):
        execute(request)
    assert len(repository.list_events_by_run(request.run_id)) == event_count


def test_trace_query_must_recover_the_same_evidence(tmp_path, scenarios, monkeypatch):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")
    monkeypatch.setattr(repository, "list_events_by_trace", lambda trace_id: [])
    with pytest.raises(ValueError, match="Evidence"):
        RuntimeTrialAdapter(repository)(trial(scenarios["BENIGN-001"]))


def test_sqlite_evidence_releases_windows_file_handles_after_trial(tmp_path, scenarios):
    """A completed run's evidence directory can be removed immediately."""
    from pathlib import Path
    from tempfile import TemporaryDirectory

    with TemporaryDirectory(dir=tmp_path) as directory:
        database = Path(directory) / "evidence.db"
        repository = SQLiteEvidenceRepository(database)
        request = trial(scenarios["BENIGN-001"])
        RuntimeTrialAdapter(repository)(request)
        assert repository.list_events_by_run(request.run_id)
        assert database.exists()
    assert not Path(directory).exists()


def test_runtime_completed_after_real_guard_error_is_not_a_valid_sample(tmp_path, scenarios, monkeypatch):
    from security.plugins.guards.input_guard import InputGuard

    def failing_inspect(self, observation, context):
        raise RuntimeError("synthetic InputGuard execution failure")

    monkeypatch.setattr(InputGuard, "inspect", failing_inspect)
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")
    execute = RuntimeTrialAdapter(repository)
    request = trial(scenarios["BENIGN-001"], "B")
    with pytest.raises(ValueError, match="(?i)guard"):
        execute(request)
    assert execute.trials[-1]["run_status"] == "COMPLETED"
    assert execute.trials[-1]["evidence_validated"] is False
    guard_events = [event for event in repository.list_events_by_run(request.run_id) if event.event_type == "SECURITY_RESULT"]
    assert any(event.payload["execution_status"] == "ERROR" for event in guard_events)


@pytest.mark.parametrize("status,error", [
    ("ERROR", None),
    ("TIMEOUT", None),
    ("SUCCESS", {"code": "SYNTHETIC_GUARD_ERROR", "message": "test"}),
])
def test_guard_failure_evidence_cannot_enter_completed_metrics(tmp_path, scenarios, monkeypatch, status, error):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")
    save = repository.save_event

    def save_guard_failure(event):
        if event.event_type == "SECURITY_RESULT":
            event = event.model_copy(update={"payload": {**event.payload, "execution_status": status, "error": error}})
        save(event)

    monkeypatch.setattr(repository, "save_event", save_guard_failure)
    execute = RuntimeTrialAdapter(repository)
    with pytest.raises(ValueError, match="(?i)guard"):
        execute(trial(scenarios["BENIGN-001"], "B"))
    assert execute.trials[-1]["run_status"] == "COMPLETED"
    assert execute.trials[-1]["evidence_validated"] is False
