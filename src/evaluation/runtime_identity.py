"""Evaluation-local bindings to unchanged Runtime identities and SQLite events."""

from .mcp_trial_observation import BackendObservation


def candidate_identity(obs, candidate_id, run_id, trace_id):
    matches = [m for m in obs.runtime_bindings if m.candidate_id == candidate_id]
    if len(matches) > 1:
        raise ValueError("ambiguous Runtime candidate binding")
    return (matches[0].runtime_run_id, matches[0].runtime_trace_id) if matches else (run_id, trace_id)


def evidence_identity(obs, ref, run_id, trace_id):
    matches = [m for m in obs.runtime_bindings if ref in m.runtime_evidence_refs]
    if len(matches) > 1:
        raise ValueError("ambiguous Runtime Evidence binding")
    return (matches[0].runtime_run_id, matches[0].runtime_trace_id) if matches else (run_id, trace_id)


def binding_issues(
    obs: BackendObservation, scope, run_id, trace_id, scenario_id, lookup,
):
    """An explicit persisted link is required; identity pairs alone are insufficient.

    Links are Evaluation attestations, not Runtime Security events. Validate them
    again when reading sidecars so edits cannot silently reassign Evidence.
    """
    issues = []
    if not obs.runtime_bindings:
        return issues
    if scope != "actual_llm_mcp":
        return ["runtime_binding_requires_actual_scope"]
    candidates = {c.candidate_id: c for c in obs.candidates}
    seen_candidates, seen_runs, seen_traces, seen_refs, seen_links = set(), set(), set(), set(), set()
    for binding in obs.runtime_bindings:
        if (
            binding.trial_run_id != run_id or binding.trial_trace_id != trace_id
            or binding.scenario_id != scenario_id
            or binding.candidate_id not in candidates
            or binding.candidate_id in seen_candidates
            or binding.runtime_run_id in seen_runs or binding.runtime_trace_id in seen_traces
            or binding.runtime_run_id == run_id or binding.runtime_trace_id == trace_id
            or binding.link_evidence_ref in seen_links
            or len(binding.runtime_evidence_refs) != len(set(binding.runtime_evidence_refs))
            or seen_refs.intersection(binding.runtime_evidence_refs)
        ):
            issues.append("runtime_binding_identity_mismatch")
        seen_candidates.add(binding.candidate_id)
        seen_runs.add(binding.runtime_run_id)
        seen_traces.add(binding.runtime_trace_id)
        seen_links.add(binding.link_evidence_ref)
        seen_refs.update(binding.runtime_evidence_refs)
        candidate = candidates.get(binding.candidate_id)
        if candidate is not None and set(candidate.evidence_refs or []) != set(binding.runtime_evidence_refs):
            issues.append("runtime_binding_candidate_refs_mismatch")
        if binding.link_evidence_ref not in (obs.evidence_refs or []):
            issues.append("runtime_binding_link_not_referenced")
        try:
            link = lookup(binding.link_evidence_ref) if lookup else None
            if link is None or (
                link.event_id != binding.link_evidence_ref
                or link.event_type != "EVALUATION_RUNTIME_LINK"
                or (link.run_id, link.trace_id, link.scenario_id) != (run_id, trace_id, scenario_id)
                or link.payload != binding.model_dump(mode="json", exclude={"link_evidence_ref"})
            ):
                issues.append("runtime_binding_link_unverified")
            for ref in binding.runtime_evidence_refs:
                event = lookup(ref) if lookup else None
                if event is None or (
                    event.event_id != ref
                    or (event.run_id, event.trace_id, event.scenario_id)
                    != (binding.runtime_run_id, binding.runtime_trace_id, scenario_id)
                ):
                    issues.append("runtime_binding_evidence_unverified")
            if candidate is not None:
                snapshots = [("SECURITY_DECISION", candidate.security_decision)]
                snapshots += [("SECURITY_RESULT", item) for item in candidate.guard_results or []]
                for kind, snapshot in snapshots:
                    if snapshot is None:
                        continue
                    if (snapshot.run_id, snapshot.trace_id) != (
                        binding.runtime_run_id, binding.runtime_trace_id,
                    ) or not any(
                        (event := lookup(ref)) is not None and event.event_type == kind
                        and event.payload == snapshot.model_dump(mode="json")
                        for ref in binding.runtime_evidence_refs
                    ):
                        issues.append("runtime_binding_snapshot_unverified")
        except Exception:  # noqa: BLE001 - unverifiable bindings never authorize identity changes
            issues.append("runtime_binding_lookup_failed")
    if seen_links & seen_refs:
        issues.append("runtime_binding_link_reused_as_runtime_event")
    return issues
