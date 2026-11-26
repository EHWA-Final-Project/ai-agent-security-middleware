"""Offline contracts: synthetic Runtime observations, real private SQLite storage.

No test here is an actual-model experiment or evidence of security effectiveness.
"""

import asyncio
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path

import pytest
from schemas.evidence import SecurityEvent
from schemas.security import SecurityDecision, SecurityResult

from evaluation.external_mcp_adapter import build_bipia_pair
from evaluation.external_mcp_evidence import EvidenceView
from evaluation.external_mcp_judges import judge_trial
from evaluation.external_mcp_runtime_backend import (
    RuntimeExecutionBackend,
    runtime_model_configuration,
    runtime_policy,
)
from evaluation.external_mcp_trial_runner import (
    ExternalMCPTrialRunner,
    TrialConfig,
    TrialRequest,
    UnavailableConfiguration,
)
from evaluation.mcp_external_manifest import BIPIA_PROVENANCE_FIELDS, build_manifest
from evaluation.mcp_trial_observation import BackendObservation, TrialSidecar
from evidence.sqlite_repository import SQLiteEvidenceRepository


@pytest.fixture
def setup(monkeypatch, tmp_path):
    monkeypatch.setenv("LLM_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("LLM_MODEL", "offline-contract-model")
    monkeypatch.setenv("LLM_TIMEOUT_SEC", "180")
    monkeypatch.delenv("LLM_MAX_TOKENS", raising=False)
    monkeypatch.delenv("LLM_MAX_TOKENS_PARAM", raising=False)
    metadata = dict.fromkeys(BIPIA_PROVENANCE_FIELDS, "synthetic-contract-metadata")
    metadata.update(pair_id="contract-pair", dataset_id="bipia")
    cases = build_bipia_pair(
        {"context": "Synthetic answer: 42.", "question": "What number?", "ideal": "42"},
        "Synthetic test instruction.", metadata,
    )
    case = cases[0]
    manifest = build_manifest(cases, "")
    cfg = TrialConfig(
        experiment_id="offline-backend-contract", condition="C", code_revision="test",
        execution_scope="actual_llm_mcp", model=runtime_model_configuration(),
    )
    backend = RuntimeExecutionBackend(tmp_path / "private")
    runner = ExternalMCPTrialRunner(
        backend=backend, policy_resolver=runtime_policy, evidence_lookup=backend.events.get,
    )
    return case, manifest, cfg, backend, runner


def install_runtime(monkeypatch, setup, *, mode="normal"):
    """Patch only the public Runtime entry point, keeping production bridge code."""
    from examples import run_agent_mcp_e2e as runtime

    calls = []

    async def execute(portal, directory, condition, case, *, trial_run_id, trial_trace_id, output_injection_scan):
        from agent_mcp_observation import AgentRunObservation

        assert portal is not None
        assert not directory.exists()
        directory.mkdir()
        resolved = runtime_policy(setup[2].model_copy(update={
            "condition": condition, "output_injection_scan": output_injection_scan,
        }))
        obs = AgentRunObservation(
            scenario_id=case.scenario_id, condition=condition,
            trial_run_id=trial_run_id, trial_trace_id=trial_trace_id,
            requested_model=setup[2].model["name"], policy_version=resolved.version,
            output_injection_scan=resolved.configuration.policy.output_injection_scan,
            initial_inspection_mode=resolved.configuration.policy.initial_inspection_mode.value,
        )
        calls.append((case, obs, directory))
        if mode == "raise":
            raise RuntimeError("RAW PRIVATE ERROR MUST NOT BE EXPORTED")
        if mode == "wait":
            try:
                await asyncio.sleep(10)
            finally:
                calls.append("cancelled")
        if mode == "empty":
            return obs
        obs.record_model_turn(1, "returned-model-version", {
            "finish_reason": "tool_calls", "tool_call_observations": [{
                "index": 0, "model_tool_call_id": "provider-call-1",
                "provider_tool_name": "demo__read_file", "arguments_valid": True,
            }],
        })
        item = obs.record_tool_candidate(
            1, "demo__read_file", "demo/read_file", "provider-call-1", {"path": "docs/benchmark.txt"},
        )
        if mode == "partial":
            obs.mark_error("runtime_execution", "RUNTIME_FAILED")
            return obs
        item.run_id, item.trace_id = "runtime-run-1", "runtime-trace-1"
        item.runtime_scenario_id = case.scenario_id
        item.runtime_tool_call_id = "runtime-tool-1"
        item.runtime_status = "COMPLETED"
        item.sdk_call_count = 1
        item.server_call_counts = {"read_file": 1, "send_email": 0}
        item.tool_executed = True
        item.execution_state = "EXECUTED"
        item.output_allowed = True
        item.output_delivered = True
        item.output_destination = "model"
        decision = SecurityDecision(
            run_id=item.run_id, trace_id=item.trace_id, decision="ALLOW", reason="contract",
            cumulative_risk_score=0, policy_version=obs.policy_version,
        )
        guard = SecurityResult(
            run_id=item.run_id, trace_id=item.trace_id, stage="INPUT", guard_name="input_guard",
            execution_status="SUCCESS", risk_score=0, decision="ALLOW", latency_ms=1,
        )
        item.security_decision = "ALLOW"
        item.security_decision_snapshot = decision.model_dump(mode="json")
        repository = SQLiteEvidenceRepository(directory / "evidence.db")
        obs.evidence_db_path = str(directory / "evidence.db")
        for ref, kind, snapshot in [
            ("original-decision-id", "SECURITY_DECISION", decision),
            ("original-result-id", "SECURITY_RESULT", guard),
        ]:
            repository.save_event(SecurityEvent(
                event_id=ref, run_id=item.run_id, trace_id=item.trace_id,
                scenario_id=case.scenario_id, event_type=kind, payload=snapshot.model_dump(mode="json"),
            ))
        item.record_evidence(repository.list_events_by_run(item.run_id))
        obs.record_model_turn(2, "returned-model-version", {
            "finish_reason": "stop", "tool_call_observations": [],
        }, response_text="42")
        obs.final_response = "42"
        obs.mark_completed()
        obs.finalize_candidate_trace()
        obs.finalize_guard_trace()
        if mode == "runtime_error":
            obs.mark_error("runtime_execution", "RUNTIME_FAILED")
        elif mode == "runtime_timeout":
            obs.mark_error("agent_execution", "TimeoutError", timed_out=True)
        elif mode == "wrong_trial":
            obs.trial_trace_id = "foreign-trial"
        elif mode == "wrong_policy":
            obs.policy_version = "foreign-policy"
        elif mode == "wrong_model":
            obs.requested_model = "foreign-model"
        elif mode == "missing_evidence":
            # Runtime observations still claim refs: bridge must not supply replacements.
            Path(obs.evidence_db_path).unlink()
        elif mode == "changed_snapshot":
            item.security_decision_snapshot["reason"] = "not the persisted snapshot"
        elif mode == "no_tool":
            obs.tool_executions.clear()
            obs.model_turns = obs.model_turns[-1:]
            obs.model_turns[0].turn = 1
            obs.finalize_candidate_trace()
            obs.finalize_guard_trace()
        calls.append(deepcopy(asdict(obs)))
        return obs

    monkeypatch.setattr(runtime, "execute_agent_case", execute)
    return calls


def run(setup):
    case, manifest, cfg, _, runner = setup
    return asyncio.run(runner.run(case, manifest, cfg))


def test_original_identities_snapshots_and_sqlite_are_preserved(setup, monkeypatch):
    calls = install_runtime(monkeypatch, setup)
    trial = run(setup)
    backend = setup[3]
    candidate = trial.observation.candidates[0]
    raw = calls[-1]
    assert trial.observation.run_status == "completed"
    assert trial.evidence_validated is True
    assert candidate.security_decision.run_id == "runtime-run-1" != trial.run_id
    assert candidate.security_decision.trace_id == "runtime-trace-1" != trial.trace_id
    assert candidate.security_decision.model_dump(mode="json") == raw["tool_executions"][0]["security_decision_snapshot"]
    assert candidate.guard_results[0].model_dump(mode="json") == raw["tool_executions"][0]["security_result_snapshots"][0]
    assert candidate.evidence_refs == ["original-decision-id", "original-result-id"]
    assert candidate.model_tool_call_id == "provider-call-1"
    assert candidate.mcp_call_id == "runtime-tool-1"
    assert candidate.sdk_call_count == 1
    assert candidate.server_tool_body_counts == {"read_file": 1, "send_email": 0}
    assert candidate.call_count is None
    assert candidate.guard_decision is candidate.tool_policy_decision is None
    assert candidate.prevention_sources is None
    assert candidate.output_delivered is True
    assert trial.observation.output_delivered is None
    assert trial.observation.sdk_calls is None
    assert trial.observation.runtime_model_names == ["returned-model-version"] * 2
    assert trial.output_injection_scan is False
    assert trial.policy_enabled is True
    binding = trial.observation.runtime_bindings[0]
    repository = SQLiteEvidenceRepository(calls[0][2] / "evidence.db")
    assert [e.event_id for e in repository.list_events_by_run("runtime-run-1")] == candidate.evidence_refs
    assert repository.list_events_by_run(trial.run_id)[0] == backend.events[binding.link_evidence_ref]
    assert EvidenceView(trial, backend.events.get).base_reason() is None
    assert TrialSidecar.model_validate_json(trial.model_dump_json()) == trial
    judged = judge_trial(trial, setup[0], backend.events.get)
    assert judged.observation.semantic_outcomes.task.value is None
    assert judged.observation.semantic_outcomes.attack.value is None
    # The case and Runtime observations were not mutated by conversion.
    assert asdict(calls[0][1]) == raw
    assert calls[0][0].documents == {"docs/benchmark.txt": setup[0]["document_content"]}


@pytest.mark.parametrize("mode,status", [
    ("empty", "incomplete"), ("partial", "error"), ("raise", "error"),
    ("runtime_error", "error"), ("runtime_timeout", "timeout"),
    ("wrong_trial", "error"), ("wrong_policy", "error"), ("wrong_model", "error"),
    ("missing_evidence", "error"), ("changed_snapshot", "incomplete"), ("no_tool", "incomplete"),
])
def test_errors_and_missing_observations_never_become_defense(setup, monkeypatch, mode, status):
    install_runtime(monkeypatch, setup, mode=mode)
    trial = run(setup)
    assert trial.observation.run_status == status
    assert trial.observation.attack_objective_achieved is None
    assert trial.observation.legitimate_task_success is None
    assert "RAW PRIVATE" not in trial.model_dump_json()
    if mode == "empty":
        assert trial.observation.model_tool_selection_observed is None
        assert trial.observation.candidates == []
    if mode == "partial":
        c = trial.observation.candidates[0]
        assert c.model_selected_tool is not None
        assert c.requested_tool is c.security_decision is c.tool_executed is None
    if mode == "no_tool":
        assert trial.observation.model_tool_selection_observed is True
        assert trial.observation.candidate_trace_complete is True
        assert trial.observation.candidates == []
    if mode == "missing_evidence":
        assert trial.observation.candidates[0].tool_executed is True
        assert trial.evidence_validated is False
    if mode == "runtime_timeout":
        assert trial.observation.timed_out is True
        assert trial.observation.candidates[0].tool_executed is True


@pytest.mark.parametrize("changes", [
    {"seed": 7},
    {"execution_scope": "fixture_execution"},
])
def test_unavailable_configuration_before_io(setup, monkeypatch, changes):
    calls = install_runtime(monkeypatch, setup)
    case, manifest, cfg, backend, runner = setup
    cfg = cfg.model_copy(update=changes)
    with pytest.raises(UnavailableConfiguration):
        asyncio.run(runner.run(case, manifest, cfg))
    assert not calls
    assert not backend.private_root.exists()


def test_environment_model_mismatch_before_io(setup, monkeypatch):
    calls = install_runtime(monkeypatch, setup)
    monkeypatch.setenv("LLM_MODEL", "different-model")
    trial = run(setup)
    assert trial.observation.run_status == "error"
    assert trial.observation.error_detail == "UnavailableConfiguration"
    assert not calls
    assert not setup[3].private_root.exists()


@pytest.mark.parametrize("condition,enabled", [("A", False), ("B", True), ("C", True), ("D", True)])
def test_policy_resolution_matches_runtime_tool_guard(setup, condition, enabled):
    policy = runtime_policy(setup[2].model_copy(update={"condition": condition}))
    assert policy.enabled is enabled
    assert policy.configuration.policy.output_injection_scan is False
    assert f"-cond-{condition.lower()}-" in policy.version


@pytest.mark.parametrize("tamper", [
    "link", "link_removed", "runtime_trace", "payload_trace", "candidate_ref", "snapshot",
    "duplicate_binding", "fixture_scope", "scenario", "unmapped_foreign_event",
])
def test_mapping_validation_rejects_tampering(setup, monkeypatch, tamper):
    install_runtime(monkeypatch, setup)
    trial = run(setup)
    events = deepcopy(setup[3].events)
    binding = trial.observation.runtime_bindings[0]
    event = events["original-decision-id"]
    if tamper == "link":
        events[binding.link_evidence_ref].payload["runtime_run_id"] = "foreign"
    elif tamper == "link_removed":
        events.pop(binding.link_evidence_ref)
    elif tamper == "runtime_trace":
        event.trace_id = "foreign"
    elif tamper == "payload_trace":
        event.payload["trace_id"] = "foreign"
    elif tamper == "candidate_ref":
        trial.observation.candidates[0].evidence_refs = []
    elif tamper == "snapshot":
        trial.observation.candidates[0].security_decision.reason = "changed"
    elif tamper == "duplicate_binding":
        trial.observation.runtime_bindings.append(binding.model_copy(deep=True))
    elif tamper == "fixture_scope":
        trial.execution_scope = "fixture_execution"
    elif tamper == "scenario":
        event.scenario_id = "foreign"
    else:
        events["foreign"] = event.model_copy(update={"event_id": "foreign"})
        trial.observation.evidence_refs.append("foreign")
    view = EvidenceView(trial, events.get)
    assert view.base_reason() is not None
    validated, issues = ExternalMCPTrialRunner(evidence_lookup=events.get)._check_evidence(
        trial.observation, trial.run_id, trial.trace_id, trial.scenario_id,
        trial.policy_version, trial.execution_scope,
    )
    assert validated is False
    assert issues


def test_timeout_and_external_cancellation_propagate(setup, monkeypatch):
    calls = install_runtime(monkeypatch, setup, mode="wait")
    setup[2].timeout_seconds = 0.03
    trial = run(setup)
    assert trial.observation.run_status == "timeout"
    assert trial.observation.timed_out is True
    assert "cancelled" in calls
    assert trial.observation.candidates == []
    assert "runtime_partial_observation" in trial.observation.unknown_reasons
    assert trial.observation.model_tool_selection_observed is None
    assert setup[3]._running is False

    async def cancel():
        obs = BackendObservation()
        request = TrialRequest("trial", "trace", setup[0], setup[2], runtime_policy(setup[2]))
        task = asyncio.create_task(setup[3].execute(request, obs))
        await asyncio.sleep(0.03)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert setup[3]._running is False

    asyncio.run(cancel())


def test_reject_repository_private_output():
    from evaluation.external_mcp_runtime_backend import ROOT

    with pytest.raises(ValueError, match="outside repositories"):
        RuntimeExecutionBackend(ROOT / "private")


@pytest.mark.parametrize("condition", ["A", "B", "C", "D"])
@pytest.mark.parametrize("scan", [False, True])
def test_backend_delegates_supported_condition(setup, monkeypatch, condition, scan):
    setup[2].condition = condition
    setup[2].output_injection_scan = scan
    calls = install_runtime(monkeypatch, setup)
    trial = run(setup)
    assert calls[0][1].condition == condition
    assert calls[0][1].output_injection_scan is scan
    assert trial.output_injection_scan is scan
    assert calls[0][1].initial_inspection_mode == ("FAST" if condition == "D" else "STANDARD")
    assert trial.observation.run_status == "completed"
    assert trial.evidence_validated is True
    assert trial.policy_enabled is (condition != "A")


def test_missing_lookup_never_validates_mapping(setup, monkeypatch):
    install_runtime(monkeypatch, setup)
    setup[4].evidence_lookup = None
    trial = run(setup)
    assert trial.evidence_validated is False
    assert trial.observation.run_status == "incomplete"
    assert "runtime_binding_link_unverified" in trial.evidence_issues


def test_missing_server_counts_and_sdk_counts_stay_unknown(setup, monkeypatch):
    from examples import run_agent_mcp_e2e as runtime

    install_runtime(monkeypatch, setup)
    original = runtime.execute_agent_case

    async def missing(*args, **kwargs):
        raw = await original(*args, **kwargs)
        item = raw.tool_executions[0]
        item.sdk_call_count = None
        item.server_call_counts = None
        item.output_delivered = None
        item.output_destination = None
        return raw

    monkeypatch.setattr(runtime, "execute_agent_case", missing)
    trial = run(setup)
    item = trial.observation.candidates[0]
    assert item.sdk_call_count is item.server_tool_body_counts is item.call_count is None
    assert item.output_delivered is None
    assert item.output_allowed is True


def test_two_runtime_requests_have_separate_bindings_and_parent_link(setup, monkeypatch):
    from examples import run_agent_mcp_e2e as runtime

    install_runtime(monkeypatch, setup)
    original = runtime.execute_agent_case

    async def two(*args, **kwargs):
        raw = await original(*args, **kwargs)
        second = deepcopy(raw.tool_executions[0])
        second.candidate_id = "candidate-2"
        second.parent_candidate_id = "candidate-1"
        second.model_tool_call_id = "provider-call-2"
        second.runtime_tool_call_id = "runtime-tool-2"
        second.run_id, second.trace_id = "runtime-run-2", "runtime-trace-2"
        second.security_decision_snapshot.update(run_id=second.run_id, trace_id=second.trace_id)
        repository = SQLiteEvidenceRepository(raw.evidence_db_path)
        for event in repository.list_events_by_run("runtime-run-1"):
            payload = {**event.payload, "run_id": second.run_id, "trace_id": second.trace_id}
            repository.save_event(event.model_copy(update={
                "event_id": event.event_id + "-2", "run_id": second.run_id,
                "trace_id": second.trace_id, "payload": payload,
            }))
        second.record_evidence(repository.list_events_by_run(second.run_id))
        raw.tool_executions.append(second)
        raw.candidate_trace_complete = False  # This synthetic trace omits the second model turn.
        raw.guard_trace_complete = False
        return raw

    monkeypatch.setattr(runtime, "execute_agent_case", two)
    trial = run(setup)
    assert trial.evidence_validated is True
    assert len(trial.observation.runtime_bindings) == 2
    first, second = trial.observation.candidates
    assert second.parent_mcp_call_id == first.mcp_call_id
    assert second.parent_candidate_id == first.candidate_id
    assert second.security_decision.run_id != first.security_decision.run_id
    assert EvidenceView(trial, setup[3].events.get).base_reason() is None


def test_counts_do_not_fabricate_sdk_metric_or_guard_metric(setup, monkeypatch):
    from evaluation.external_mcp_metrics import aggregate_external

    install_runtime(monkeypatch, setup)
    trial = run(setup)
    bundle = aggregate_external([trial], setup[3].events.get)
    # Inspect the public aggregation, not just unknown fields on the raw sidecar.
    encoded = __import__("json").dumps(bundle)
    assert "sdk_trace_unknown" in encoded
    assert "guard_or_candidate_trace_incomplete" in encoded
    assert "independent_judgment_missing" in encoded


@pytest.mark.parametrize("field,value,status", [
    ("output_injection_scan", True, "error"),
    ("initial_inspection_mode", "FAST", "error"),
    ("output_injection_scan", None, "incomplete"),
    ("initial_inspection_mode", None, "incomplete"),
])
def test_runtime_configuration_must_be_observed(setup, monkeypatch, field, value, status):
    from examples import run_agent_mcp_e2e as runtime

    install_runtime(monkeypatch, setup)
    original = runtime.execute_agent_case

    async def changed(*args, **kwargs):
        raw = await original(*args, **kwargs)
        setattr(raw, field, value)
        return raw

    monkeypatch.setattr(runtime, "execute_agent_case", changed)
    assert run(setup).observation.run_status == status
