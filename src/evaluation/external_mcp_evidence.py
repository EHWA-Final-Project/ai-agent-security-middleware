"""Read-only Evidence linkage checks shared by external evaluation consumers."""

from collections.abc import Callable

from schemas.evidence import SecurityEvent

from .mcp_trial_observation import TrialSidecar

EvidenceLookup = Callable[[str], SecurityEvent | None]


class EvidenceView:
    def __init__(self, trial: TrialSidecar, lookup: EvidenceLookup):
        self.trial = trial
        self.lookup = lookup

    def get(self, ref: str, kind: str | None = None) -> SecurityEvent | None:
        try:
            event = self.lookup(ref)
        except Exception:  # noqa: BLE001 - unavailable evidence never establishes a fact
            return None
        t = self.trial
        if event is None or (
            event.event_id != ref or event.run_id != t.run_id or event.trace_id != t.trace_id
            or event.scenario_id not in (None, t.scenario_id)
            or (kind is not None and event.event_type != kind)
            or not isinstance(event.payload, dict)
        ):
            return None
        for key, expected in (
            ("run_id", t.run_id), ("trace_id", t.trace_id), ("scenario_id", t.scenario_id),
            ("sample_id", t.sample_id), ("mapped_case_sha256", t.mapped_case_sha256),
            ("policy_version", t.policy_version),
        ):
            if key in event.payload and event.payload[key] != expected:
                return None
        # Semantic facts need explicit scenario linkage, not only a shared session.
        if kind is not None and event.scenario_id != t.scenario_id:
            return None
        return event

    def supports(self, refs) -> bool:
        return bool(refs) and all(self.get(ref) is not None for ref in refs)

    def base_reason(self) -> str | None:
        t, obs = self.trial, self.trial.observation
        if t.execution_scope == "mapping_only":
            return "mapping_only"
        if obs.run_status != "completed":
            return f"status:{obs.run_status or 'unknown'}"
        if obs.timed_out is True or obs.error_stage or obs.error_detail:
            return "error_or_timeout_diagnostics"
        if t.evidence_validated is not True or t.evidence_issues:
            return "evidence_not_validated"
        if t.policy_enabled is None:
            return "policy_configuration_unknown"
        if t.execution_scope == "actual_llm_mcp" and not t.model:
            return "model_configuration_unknown"
        if t.provenance.get("source_type") != "external_adapted":
            return "not_external_adapted"
        refs = list(obs.evidence_refs or [])
        if not refs:
            return "run_evidence_missing"
        refs.extend(obs.model_response_refs or [])
        refs.extend(obs.payload_exposure_refs or [])
        for candidate in obs.candidates:
            if t.execution_scope == "actual_llm_mcp" and candidate.candidate_source != "model":
                return "actual_trial_candidate_not_model_observed"
            if t.execution_scope != "actual_llm_mcp" and candidate.model_selected_tool is not None:
                return "fixture_cannot_claim_model_selection"
            if not candidate.evidence_refs:
                return "candidate_evidence_missing"
            refs.extend(candidate.evidence_refs)
            refs.extend(candidate.prevention_evidence_refs or [])
            for snapshot in [candidate.security_decision, *(candidate.guard_results or [])]:
                if snapshot is not None and (
                    snapshot.run_id != t.run_id or snapshot.trace_id != t.trace_id
                ):
                    return "snapshot_identity_mismatch"
                if snapshot is not None and not any(
                    (event := self.get(ref)) is not None
                    and event.event_type == (
                        "SECURITY_DECISION" if snapshot is candidate.security_decision else "SECURITY_RESULT"
                    )
                    and event.payload == snapshot.model_dump(mode="json")
                    for ref in candidate.evidence_refs
                ):
                    return "security_snapshot_evidence_missing"
            if candidate.security_decision is not None and (
                candidate.security_decision.policy_version != t.policy_version
            ):
                return "snapshot_policy_mismatch"
        for call in obs.sdk_calls or []:
            if not call.evidence_ref:
                return "sdk_evidence_missing"
            refs.append(call.evidence_ref)
            event = self.get(call.evidence_ref, "SDK_INVOCATION")
            if event is None or (
                event.payload.get("method") != call.method
                or event.payload.get("invoked") is not True
                or event.payload.get("candidate_id") != call.candidate_id
                or event.payload.get("mcp_call_id") != call.mcp_call_id
            ):
                return "sdk_invocation_evidence_mismatch"
        return None if self.supports(refs) else "evidence_missing_or_mismatched"

    def exposure_observed(self) -> bool:
        for ref in self.trial.observation.payload_exposure_refs or []:
            event = self.get(ref, "PAYLOAD_EXPOSURE")
            if event and (
                event.payload.get("exposed_to_model") is True
                and event.payload.get("mapped_case_sha256") == self.trial.mapped_case_sha256
                and event.payload.get("entry_surface") == self.trial.provenance.get("entry_surface")
            ):
                return True
        return False
