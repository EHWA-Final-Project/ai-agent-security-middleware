"""Injected external MCP trials. No model client, attack server or metric logic."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from time import perf_counter
from typing import Any, Literal, Protocol
from uuid import NAMESPACE_URL, uuid5

from pydantic import Field
from schemas.evidence import SecurityEvent

from security.policy.conditions import load_condition

from .external_mcp_adapter import record_sha256
from .mcp_external_manifest import case_metadata
from .mcp_trial_observation import (
    BackendObservation,
    Count,
    Identifier,
    ObservationModel,
    Scope,
    TrialSidecar,
)


class UnavailableConfiguration(ValueError):
    """Requested backend or policy is unavailable; never substitute a baseline."""


class TrialConfig(ObservationModel):
    experiment_id: Identifier
    condition: Literal["A", "B", "C", "D"]
    repeat: Count = 0
    seed: int | None = None
    model: dict[str, Any] | None = None
    execution_scope: Scope = "fixture_execution"
    output_injection_scan: bool = False
    timeout_seconds: float = Field(default=30.0, gt=0)
    code_revision: Identifier
    policy_comparison_key: Identifier | None = None


@dataclass(frozen=True)
class ResolvedPolicy:
    version: str
    # ToolPolicy enforcement is a separate fact, never inferred from A/B/C/D.
    enabled: bool | None
    configuration: Any


def resolve_policy(config: TrialConfig) -> ResolvedPolicy:
    kwargs = {}
    if "output_injection_scan" in inspect.signature(load_condition).parameters:
        kwargs["output_injection_scan"] = config.output_injection_scan
    elif config.output_injection_scan:
        raise UnavailableConfiguration("PI-T01 output inspection is unavailable")
    try:
        condition = load_condition(config.condition, **kwargs)
    except (ValueError, FileNotFoundError) as exc:
        raise UnavailableConfiguration(f"policy {config.condition} is unavailable") from exc
    return ResolvedPolicy(condition.policy.policy_version, None, condition)


@dataclass(frozen=True)
class TrialRequest:
    run_id: str
    trace_id: str
    case: dict[str, Any]
    config: TrialConfig
    policy: ResolvedPolicy


class ExecutionBackend(Protocol):
    """Must honor cancellation; connect Runtime here, without reimplementing it.

    Append observations before awaiting later work so timeout retains facts.
    Raw case fields remain untrusted. Never promote them to system instructions.
    Backend IDs must version changes to execution behavior.
    """

    backend_id: str
    execution_scope: Literal["fixture_execution", "actual_llm_mcp"]

    async def execute(self, request: TrialRequest, observation: BackendObservation) -> None: ...


class ExternalMCPTrialRunner:
    def __init__(
        self,
        *,
        backend: ExecutionBackend | None = None,
        policy_resolver: Callable[[TrialConfig], ResolvedPolicy] = resolve_policy,
        evidence_lookup: Callable[[str], SecurityEvent | None] | None = None,
    ):
        self.backend = backend
        self.policy_resolver = policy_resolver
        self.evidence_lookup = evidence_lookup

    async def run(self, case: dict, manifest: dict, config: TrialConfig) -> TrialSidecar:
        # Snapshot inputs; injected code cannot mutate the caller's mappings.
        case, manifest = deepcopy(case), deepcopy(manifest)
        config = TrialConfig.model_validate(config.model_dump())
        metadata = self._verify_mapping(case, manifest)
        policy = self.policy_resolver(config.model_copy(deep=True))
        if not isinstance(policy.version, str) or not policy.version.strip():
            raise UnavailableConfiguration("resolved policy needs a version")
        backend_id = None
        if config.execution_scope != "mapping_only":
            if self.backend is None:
                raise UnavailableConfiguration("execution backend is unavailable")
            if self.backend.execution_scope != config.execution_scope:
                raise UnavailableConfiguration("backend execution scope mismatch")
            backend_id = self.backend.backend_id
            if not isinstance(backend_id, str) or not backend_id.strip():
                raise UnavailableConfiguration("backend needs a versioned identifier")
            if config.execution_scope == "actual_llm_mcp" and not config.model:
                raise UnavailableConfiguration("actual execution requires model information")
        manifest_hash = record_sha256(manifest)
        identity = record_sha256({
            "config": config.model_dump(), "manifest": manifest_hash,
            "sample": case["sample_id"], "case": metadata["mapped_case_sha256"],
            "policy": policy.version, "policy_enabled": policy.enabled,
            "backend": backend_id,
        })
        run_id = f"mcp-run-{uuid5(NAMESPACE_URL, identity)}"
        trace_id = f"mcp-trace-{uuid5(NAMESPACE_URL, run_id)}"
        observation = BackendObservation()
        started_at = datetime.now(UTC)
        latency_ms = None
        if config.execution_scope != "mapping_only":
            request = TrialRequest(
                run_id, trace_id, deepcopy(case), config.model_copy(deep=True), deepcopy(policy),
            )
            started = perf_counter()
            try:
                async with asyncio.timeout(config.timeout_seconds):
                    await self.backend.execute(request, observation)
            except TimeoutError:
                observation.run_status = "timeout"
                observation.timed_out = True
                observation.error_stage = "backend_execution"
                observation.error_detail = "execution deadline exceeded"
            except Exception as exc:  # noqa: BLE001 - preserve partial backend observations
                observation.run_status = "error"
                observation.error_stage = "backend_execution"
                # Exception text can contain raw dataset text or secrets.
                observation.error_detail = type(exc).__name__
            latency_ms = (perf_counter() - started) * 1000
        else:
            observation.unknown_reasons["run_status"] = "mapping_only_not_executed"
        # Revalidate even if an injected backend mutated an existing model.
        observation = BackendObservation.model_validate(observation.model_dump())
        self._validate_observation(observation, config, case, run_id, trace_id, policy)
        evidence_validated, issues = self._check_evidence(
            observation, run_id, trace_id, case["scenario_id"], policy.version,
        ) if config.execution_scope != "mapping_only" else (None, [])
        if config.execution_scope != "mapping_only" and (
            observation.run_status is None
            or (observation.run_status == "completed" and not evidence_validated)
        ):
            observation.run_status = "incomplete"
        if evidence_validated is False:
            for key in ("attack_objective_achieved", "legitimate_task_success"):
                if getattr(observation, key) is not None:
                    setattr(observation, key, None)
                    observation.unknown_reasons[key] = "unverified_outcome_evidence"
        observation = BackendObservation.model_validate(observation.model_dump())
        return TrialSidecar(
            run_id=run_id, trace_id=trace_id, scenario_id=case["scenario_id"],
            sample_id=case["sample_id"], pair_id=case["pair_id"],
            classification=case["classification"], condition=config.condition,
            repeat=config.repeat, seed=config.seed, model=config.model,
            policy_version=policy.version, policy_enabled=policy.enabled,
            output_injection_scan=config.output_injection_scan,
            execution_scope=config.execution_scope, backend_id=backend_id,
            manifest_sha256=manifest_hash,
            mapped_case_sha256=metadata["mapped_case_sha256"],
            code_revision=config.code_revision, provenance=metadata,
            started_at=started_at, latency_ms=latency_ms,
            timeout_seconds=config.timeout_seconds, evidence_validated=evidence_validated,
            evidence_issues=issues, observation=observation,
            experiment_id=config.experiment_id,
            policy_comparison_key=config.policy_comparison_key,
        )

    @staticmethod
    def _verify_mapping(case, manifest):
        for key in ("scenario_id", "sample_id", "pair_id"):
            if not isinstance(case.get(key), str) or not case[key].strip():
                raise ValueError(f"nonempty {key} is required")
        samples = manifest["samples"]
        ids = [row["sample_id"] for row in samples]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate manifest sample IDs")
        matches = [row for row in samples if row["sample_id"] == case["sample_id"]]
        if len(matches) != 1:
            raise ValueError("case is missing from provenance manifest")
        metadata = matches[0]
        expected = case_metadata(case, "")
        # Overlap is computed from the previous contest manifest, not this runner.
        expected["previous_attack_hash_overlap"] = metadata["previous_attack_hash_overlap"]
        if metadata != expected:
            raise ValueError("mapped case or provenance differs from manifest")
        if case["execution_scope"] != "mapping_only":
            raise ValueError("runner requires an adapter mapping, not execution results")
        return metadata

    @staticmethod
    def _validate_observation(obs, config, case, run_id, trace_id, policy):
        # Semantic assessments are produced after execution by the evaluation judge.
        # A backend must not smuggle unsupported judgments into metric eligibility.
        obs.semantic_outcomes = None
        if config.execution_scope != "actual_llm_mcp" and (
            obs.model_tool_selection_observed is True or obs.model_disposition is not None
        ):
            raise ValueError("fixture cannot claim observed model behavior")
        ids = [candidate.candidate_id for candidate in obs.candidates]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate candidate IDs")
        times = [candidate.timestamp for candidate in obs.candidates]
        if times != sorted(times):
            raise ValueError("candidate timestamps must preserve event order")
        for candidate in obs.candidates:
            if config.execution_scope != "actual_llm_mcp" and (
                candidate.candidate_source == "model" or candidate.model_selected_tool is not None
            ):
                raise ValueError("fixture cannot claim actual model selection")
            if config.execution_scope == "actual_llm_mcp" and candidate.candidate_source == "fixture":
                raise ValueError("fixed candidates must use fixture execution scope")
            snapshots = [*(candidate.guard_results or [])]
            if candidate.security_decision is not None:
                snapshots.append(candidate.security_decision)
                if candidate.security_decision.policy_version != policy.version:
                    raise ValueError("SecurityDecision policy mismatch")
            for snapshot in snapshots:
                if snapshot.run_id != run_id or snapshot.trace_id != trace_id:
                    raise ValueError("Security snapshot identity mismatch")
        for call in obs.sdk_calls or []:
            if call.candidate_id is not None and call.candidate_id not in ids:
                raise ValueError("SDK call refers to unknown candidate")
        sdk_times = [call.timestamp for call in obs.sdk_calls or []]
        if sdk_times != sorted(sdk_times):
            raise ValueError("SDK timestamps must preserve event order")
        if obs.run_status == "timeout" and obs.timed_out is not True:
            raise ValueError("timeout status requires explicit timeout information")
        if obs.run_status == "completed" and obs.timed_out is True:
            raise ValueError("completed status contradicts timeout")
        if obs.model_tool_selection_observed is False and any(
            c.model_selected_tool is not None for c in obs.candidates
        ):
            raise ValueError("model selection contradicts observation availability")
        if config.execution_scope != "actual_llm_mcp":
            for key in ("attack_objective_achieved", "legitimate_task_success"):
                setattr(obs, key, None)
                obs.unknown_reasons[key] = "fixture_or_mapping_cannot_establish_semantic_outcome"
        if case["classification"] == "benign":
            obs.attack_objective_achieved = None
            obs.unknown_reasons["attack_objective_achieved"] = "not_applicable_benign"
        for key in ("attack_objective_achieved", "legitimate_task_success"):
            if getattr(obs, key) is not None and (
                not obs.judge_version or not obs.outcome_evidence_refs
            ):
                setattr(obs, key, None)
                obs.unknown_reasons[key] = "missing_semantic_judge_or_evidence"
        if obs.run_status in {"timeout", "error"} and (
            not obs.error_stage or not obs.error_detail
        ):
            raise ValueError("timeout/error requires stage and diagnostics")

    def _check_evidence(self, obs, run_id, trace_id, scenario_id, policy_version):
        refs = set(obs.evidence_refs or [])
        refs.update(obs.outcome_evidence_refs or [])
        refs.update(obs.model_response_refs or [])
        refs.update(obs.payload_exposure_refs or [])
        issues = []
        for candidate in obs.candidates:
            if not candidate.evidence_refs:
                issues.append(f"candidate_evidence_missing:{candidate.candidate_id}")
            refs.update(candidate.evidence_refs or [])
            refs.update(candidate.prevention_evidence_refs or [])
        for call in obs.sdk_calls or []:
            if call.evidence_ref:
                refs.add(call.evidence_ref)
            else:
                issues.append("sdk_call_evidence_missing")
        if not refs:
            issues.append("evidence_refs_missing")
        if self.evidence_lookup is None:
            issues.append("evidence_lookup_unavailable")
        else:
            for ref in sorted(refs):
                try:
                    event = self.evidence_lookup(ref)
                    if event is None or event.event_id != ref:
                        issues.append(f"evidence_missing:{ref}")
                        continue
                    if event.run_id != run_id or event.trace_id != trace_id:
                        issues.append(f"evidence_identity_mismatch:{ref}")
                    if event.scenario_id not in (None, scenario_id):
                        issues.append(f"evidence_scenario_mismatch:{ref}")
                    payload = event.payload
                    if isinstance(payload, dict):
                        for key, expected in (
                            ("run_id", run_id), ("trace_id", trace_id),
                            ("scenario_id", scenario_id), ("policy_version", policy_version),
                        ):
                            if key in payload and payload[key] != expected:
                                issues.append(f"evidence_payload_mismatch:{ref}:{key}")
                except Exception:  # noqa: BLE001 - evidence failures remain diagnostic
                    issues.append(f"evidence_lookup_failed:{ref}")
        return not issues, issues
