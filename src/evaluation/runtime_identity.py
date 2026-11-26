"""Evaluation-local bindings to unchanged Runtime identities and SQLite events."""

from .mcp_trial_observation import BackendObservation

# These original EvidenceBuilder events may lack an envelope scenario_id.
_SCENARIO_OPTIONAL_EVENTS = {"RUN_STATUS", "SECURITY_RESULT", "SECURITY_DECISION"}


def runtime_event_group_matches(events, run_id, trace_id, scenario_id):
    """Check original events; require a same-request scenario anchor for null IDs.

    A missing ID is not a conflicting ID. Only known legacy event types may
    omit it, and a scenario-bearing RuntimeObservation must link the group.
    This never rewrites an event or establishes semantic attack outcomes.
    """
    events = list(events)
    if not events or not run_id or not trace_id or not scenario_id:
        return False
    if len({event.event_id for event in events}) != len(events):
        return False
    anchor = False
    needs_anchor = False
    for event in events:
        if (event.run_id, event.trace_id) != (run_id, trace_id):
            return False
        if event.scenario_id is None:
            if event.event_type not in _SCENARIO_OPTIONAL_EVENTS:
                return False
            needs_anchor = True
        elif event.scenario_id != scenario_id:
            return False
        payload = event.payload
        if not isinstance(payload, dict):
            return False
        for key, expected in (("run_id", run_id), ("trace_id", trace_id)):
            if key in payload and payload[key] != expected:
                return False
        if payload.get("scenario_id") not in (None, scenario_id):
            return False
        if (
            event.event_type == "RUNTIME_OBSERVATION"
            and event.scenario_id == scenario_id
            and payload.get("run_id") == run_id
            and payload.get("trace_id") == trace_id
            and payload.get("scenario_id") == scenario_id
        ):
            anchor = True
    return not needs_anchor or anchor


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
            events = [lookup(ref) if lookup else None for ref in binding.runtime_evidence_refs]
            if any(
                event is None or event.event_id != ref
                for ref, event in zip(binding.runtime_evidence_refs, events, strict=True)
            ) or not runtime_event_group_matches(
                events, binding.runtime_run_id, binding.runtime_trace_id, scenario_id,
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
