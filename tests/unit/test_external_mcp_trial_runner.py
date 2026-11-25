"""Offline contract tests with synthetic adapter inputs and in-memory evidence."""

import asyncio
from copy import deepcopy
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from schemas.evidence import SecurityEvent

from evaluation.external_mcp_adapter import build_bipia_pair
from evaluation.external_mcp_trial_runner import (
    ExternalMCPTrialRunner,
    ResolvedPolicy,
    TrialConfig,
    UnavailableConfiguration,
)
from evaluation.mcp_external_manifest import (
    BIPIA_PROVENANCE_FIELDS,
    MSB_PROVENANCE_FIELDS,
    build_manifest,
)
from evaluation.mcp_trial_observation import (
    CandidateObservation,
    SDKCall,
    ToolAction,
    TrialSidecar,
)
from evaluation.msb_mcp_adapter import build_msb_pair


@pytest.fixture
def inputs():
    provenance = dict.fromkeys(BIPIA_PROVENANCE_FIELDS, "synthetic-test-metadata")
    provenance.update(pair_id="test-pair", dataset_id="bipia")
    cases = build_bipia_pair(
        {"context": "Synthetic answer is 2.", "question": "What number?", "ideal": "2"},
        "Synthetic reversal instruction.", provenance,
    )
    return cases[1], build_manifest(cases, provenance["attack_text_sha256"])


def config(**changes):
    return TrialConfig(**{
        "experiment_id": "offline-contract", "condition": "C",
        "code_revision": "test-revision", **changes,
    })


class FixtureBackend:
    """A controlled in-memory test executor; does not exercise real Guards or SDK."""

    backend_id = "synthetic-fixture-v1"
    execution_scope = "fixture_execution"

    def __init__(self, behavior="success"):
        self.behavior = behavior
        self.events = {}
        self.body_calls = 0

    async def execute(self, request, observation):
        ref = "fixture-event"
        observation.evidence_refs = [ref]
        self.events[ref] = SecurityEvent(
            event_id=ref, run_id=request.run_id, trace_id=request.trace_id,
            scenario_id=request.case["scenario_id"], event_type="FIXTURE_OBSERVATION",
            payload={"run_id": request.run_id, "trace_id": request.trace_id},
        )
        observation.sdk_calls = []  # No actual MCP SDK invocations in this fixture.
        observation.run_status = "completed"
        observation.timed_out = False
        action = ToolAction.model_validate(request.case["legitimate_tool_call"])
        candidate = CandidateObservation(
            candidate_id="candidate-1", timestamp=datetime.now(UTC),
            server_name=action.server_name, tool_name=action.tool_name,
            candidate_source="fixture", requested_tool=action,
            evidence_refs=[ref],
        )
        observation.candidates.append(candidate)
        if self.behavior == "pre_block":
            candidate.guard_decision = "BLOCK"
            candidate.pre_tool_block = True
            candidate.prevention_sources = ["guard"]
            candidate.tool_executed = False
            candidate.call_count = 0
            return
        # Exercise a real Python in-memory operation, never a filesystem/network tool.
        documents = {"docs/benchmark.txt": request.case["document_content"]}
        assert documents[action.arguments["path"]]
        self.body_calls += 1
        candidate.tool_executed = True
        candidate.call_count = 1  # Simulated server receipt, not an SDK invocation.
        candidate.pre_tool_block = False
        if self.behavior == "timeout":
            await asyncio.sleep(10)
        if self.behavior == "error":
            raise RuntimeError("raw dataset contents must not appear in sidecar errors")
        candidate.guard_decision = "WARN" if self.behavior == "warn" else "ALLOW"
        candidate.warn = self.behavior == "warn"
        candidate.post_tool_output_block = self.behavior == "post_block"
        candidate.output_allowed = self.behavior != "post_block"
        candidate.output_delivered = self.behavior != "post_block"
        candidate.output_destination = "model"
        observation.output_delivered = candidate.output_delivered
        if self.behavior == "post_block":
            candidate.guard_decision = "BLOCK"
        if self.behavior == "missing_evidence":
            self.events.clear()
        if self.behavior == "wrong_evidence":
            self.events[ref].trace_id = "different-trace"
        if self.behavior == "semantic_claim":
            observation.attack_objective_achieved = True
            observation.legitimate_task_success = True


def run(inputs, behavior="success", **changes):
    backend = FixtureBackend(behavior)
    runner = ExternalMCPTrialRunner(backend=backend, evidence_lookup=backend.events.get)
    return asyncio.run(runner.run(*inputs, config(**changes))), backend


def test_success_and_json_sidecar(inputs):
    result, backend = run(inputs)
    assert result.observation.run_status == "completed"
    assert result.evidence_validated is True
    assert backend.body_calls == 1
    assert result.observation.sdk_calls == []
    assert result.observation.candidates[0].model_selected_tool is None
    assert result.execution_scope == "fixture_execution"
    assert result.provenance["previous_attack_hash_overlap"] is True
    assert result.latency_ms >= 0
    assert TrialSidecar.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize("behavior", ["pre_block", "warn", "post_block"])
def test_independent_execution_boundaries(inputs, behavior):
    result, backend = run(inputs, behavior)
    candidate = result.observation.candidates[0]
    assert result.observation.run_status == "completed"
    assert candidate.tool_executed is (behavior != "pre_block")
    assert backend.body_calls == (behavior != "pre_block")
    if behavior == "warn":
        assert candidate.warn is True
        assert candidate.output_delivered is True
    if behavior == "post_block":
        assert candidate.post_tool_output_block is True
        assert candidate.output_delivered is False
        assert candidate.call_count == 1
    assert result.observation.attack_objective_achieved is None


def test_timeout_retains_prior_execution(inputs):
    result, backend = run(inputs, "timeout", timeout_seconds=0.01)
    assert result.observation.run_status == "timeout"
    assert result.observation.timed_out is True
    assert result.observation.error_stage == "backend_execution"
    assert result.observation.candidates[0].tool_executed is True
    assert backend.body_calls == 1
    assert result.observation.candidates[0].output_delivered is None


def test_error_retains_partial_facts_without_raw_text(inputs):
    result, _ = run(inputs, "error")
    assert result.observation.run_status == "error"
    assert result.observation.error_detail == "RuntimeError"
    assert result.observation.candidates[0].tool_executed is True


@pytest.mark.parametrize("behavior", ["missing_evidence", "wrong_evidence"])
def test_incomplete_evidence(inputs, behavior):
    result, _ = run(inputs, behavior)
    assert result.observation.run_status == "incomplete"
    assert result.evidence_validated is False
    assert result.evidence_issues
    assert result.observation.candidates[0].tool_executed is True


def test_fixture_cannot_claim_semantic_success_even_numeric_reversal(inputs):
    result, _ = run(inputs, "semantic_claim")
    assert result.observation.attack_objective_achieved is None
    assert result.observation.legitimate_task_success is None
    assert "fixture" in result.observation.unknown_reasons["legitimate_task_success"]


def test_benign_attack_outcome_not_applicable(inputs):
    case, manifest = deepcopy(inputs)
    case["classification"] = "benign"
    from evaluation.mcp_external_manifest import case_metadata
    manifest["samples"] = [case_metadata(case, "")]
    result, _ = run((case, manifest))
    assert result.observation.unknown_reasons["attack_objective_achieved"] == "not_applicable_benign"


def test_deterministic_ids_and_separation(inputs):
    first, _ = run(inputs)
    second, _ = run(inputs)
    repeated, _ = run(inputs, repeat=1)
    different, _ = run(inputs, condition="B")
    assert first.run_id == second.run_id
    assert first.trace_id == second.trace_id
    assert len({first.run_id, repeated.run_id, different.run_id}) == 3


def test_mapping_only_does_not_execute(inputs):
    result = asyncio.run(ExternalMCPTrialRunner().run(
        *inputs, config(execution_scope="mapping_only"),
    ))
    assert result.observation.run_status is None
    assert result.observation.sdk_calls is None
    assert result.latency_ms is None
    assert result.evidence_validated is None
    assert result.observation.unknown_reasons["run_status"] == "mapping_only_not_executed"


@pytest.mark.parametrize("changes", [
    {}, {"condition": "D"}, {"output_injection_scan": True},
])
def test_unavailable_backend_or_policy_is_explicit(inputs, changes):
    with pytest.raises(UnavailableConfiguration):
        asyncio.run(ExternalMCPTrialRunner().run(*inputs, config(**changes)))


def test_scope_mismatch(inputs):
    with pytest.raises(UnavailableConfiguration, match="scope"):
        run(inputs, execution_scope="actual_llm_mcp", model={"name": "test-model"})


def test_d_representation_with_injected_future_policy(inputs):
    backend = FixtureBackend()
    runner = ExternalMCPTrialRunner(
        backend=backend, evidence_lookup=backend.events.get,
        policy_resolver=lambda cfg: ResolvedPolicy("test-d-policy", True, object()),
    )
    result = asyncio.run(runner.run(*inputs, config(condition="D")))
    assert result.condition == "D"
    assert result.policy_version == "test-d-policy"


@pytest.mark.parametrize("field", ["document_content", "sample_id", "pair_id"])
def test_provenance_tamper_rejected(inputs, field):
    case, manifest = deepcopy(inputs)
    case[field] = "tampered"
    with pytest.raises(ValueError):
        run((case, manifest))


def test_inputs_unchanged(inputs):
    before = deepcopy(inputs)
    run(inputs)
    assert inputs == before


def test_msb_adapter_consumed_without_source_files():
    provenance = dict.fromkeys(MSB_PROVENANCE_FIELDS, "synthetic-metadata")
    provenance["dataset_id"] = "msb"
    cases = build_msb_pair("Synthetic template {goal}", provenance)
    result, _ = run((cases[1], build_manifest(cases, "")))
    assert result.provenance["dataset_id"] == "msb"
    assert result.observation.attack_objective_achieved is None


@pytest.mark.parametrize("fields", [
    {"pre_tool_block": True, "tool_executed": True},
    {"post_tool_output_block": True, "output_delivered": True},
    {"tool_executed": True, "call_count": 0},
    {"call_count": -1}, {"call_count": True}, {"tool_executed": "false"},
])
def test_contradictions_and_invalid_types_rejected(fields):
    with pytest.raises((ValidationError, ValueError)):
        CandidateObservation(candidate_id="test", timestamp=datetime.now(UTC), **fields)


def test_unknowns_are_null_with_reasons():
    candidate = CandidateObservation(candidate_id="test", timestamp=datetime.now(UTC))
    assert candidate.call_count is None
    assert candidate.unknown_reasons["call_count"] == "not_observed"
    assert candidate.tool_policy_decision is None


def test_model_nonselection_is_distinct_from_missing_observation(inputs):
    class SelectionContractBackend(FixtureBackend):
        # Synthetic test double for a future actual backend; never an actual result.
        execution_scope = "actual_llm_mcp"

        async def execute(self, request, obs):
            self.events["selection"] = SecurityEvent(
                event_id="selection", run_id=request.run_id, trace_id=request.trace_id,
                scenario_id=request.case["scenario_id"], event_type="MODEL_SELECTION",
                payload={"selected_tools": []},
            )
            obs.evidence_refs = ["selection"]
            obs.sdk_calls = []
            obs.run_status = "completed"
            obs.model_tool_selection_observed = True

    backend = SelectionContractBackend()
    result = asyncio.run(ExternalMCPTrialRunner(
        backend=backend, evidence_lookup=backend.events.get,
    ).run(*inputs, config(execution_scope="actual_llm_mcp", model={"name": "test-double"})))
    assert result.observation.model_tool_selection_observed is True
    assert result.observation.candidates == []
    assert result.observation.attack_objective_achieved is None
    assert backend.body_calls == 0


def test_sdk_calls_remain_distinct_from_server_counts(inputs):
    class SDKContractBackend(FixtureBackend):
        async def execute(self, request, obs):
            await super().execute(request, obs)
            obs.sdk_calls = [SDKCall(
                method="tools/list", timestamp=datetime.now(UTC), evidence_ref="fixture-event",
            )]

    backend = SDKContractBackend()
    result = asyncio.run(ExternalMCPTrialRunner(
        backend=backend, evidence_lookup=backend.events.get,
    ).run(*inputs, config()))
    assert result.observation.sdk_calls[0].method == "tools/list"
    assert result.observation.candidates[0].call_count == 1
