"""A/B/C/D Runtime bridge. No replacement Agent loop and no fixture fallback.

The current Runtime returns observations only at the end of execute_agent_case.
Cancellation is propagated, but in-flight partial observations are unavailable.
Use serial execution: Runtime's diagnostic stdout/stderr are redirected privately.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import yaml
from anyio.from_thread import BlockingPortal
from schemas.evidence import SecurityEvent
from schemas.security import SecurityDecision, SecurityResult

from evidence.sqlite_repository import SQLiteEvidenceRepository
from security.policy.conditions import load_condition

from .external_mcp_adapter import record_sha256, sha256
from .external_mcp_runtime_adapter import build_agent_case_kwargs
from .external_mcp_trial_runner import ResolvedPolicy, UnavailableConfiguration
from .mcp_trial_observation import (
    CandidateObservation,
    RuntimeIdentityBinding,
    SDKCall,
    ToolAction,
)
from .runtime_identity import runtime_event_group_matches

ROOT = Path(__file__).resolve().parents[2]


def runtime_policy(config):
    """Resolve the explicit Runtime condition and PI-T01 configuration."""
    if config.execution_scope != "actual_llm_mcp":
        raise UnavailableConfiguration("Runtime backend requires actual_llm_mcp scope")
    if config.condition not in {"A", "B", "C", "D"}:
        raise UnavailableConfiguration("Unsupported Runtime condition")
    if config.seed is not None:
        raise UnavailableConfiguration("Runtime model client cannot apply a generation seed")
    condition = load_condition(
        config.condition, output_injection_scan=config.output_injection_scan,
    )
    if condition.policy.output_injection_scan != config.output_injection_scan:
        raise UnavailableConfiguration("Resolved PI-T01 setting differs from request")
    flags = yaml.safe_load(condition.config_path.read_text(encoding="utf-8"))["guards"]
    enabled = flags["tool_guard"]["enabled"]
    if type(enabled) is not bool:
        raise UnavailableConfiguration("Runtime ToolPolicy configuration is unknown")
    return ResolvedPolicy(condition.policy.policy_version, enabled, condition)


def runtime_model_configuration():
    """Nonsecret settings read by Runtime; do not log endpoint or API credentials."""
    from examples.run_agent_mcp_e2e import OpenAICompatibleLLM

    llm = OpenAICompatibleLLM.from_env()
    return {
        "name": llm.model, "temperature": llm.temperature, "max_tokens": llm.max_tokens,
        "max_tokens_param": llm.max_tokens_param, "request_timeout_seconds": llm.timeout_sec,
    }


class RuntimeExecutionBackend:
    backend_id = "external-mcp-runtime-abcd-pit01-telemetry-v3"
    execution_scope = "actual_llm_mcp"

    def __init__(self, private_root: str | Path):
        self.private_root = Path(private_root).resolve()
        if self.private_root == ROOT or ROOT in self.private_root.parents or any(
            (parent / ".git").exists() for parent in (self.private_root, *self.private_root.parents)
        ):
            raise ValueError("Runtime private output must be outside repositories")
        self.events: dict[str, SecurityEvent] = {}
        self._running = False

    async def execute(self, request, observation):
        # All unsupported settings fail before directory creation or Runtime calls.
        policy = runtime_policy(request.config)
        if request.policy != policy:
            raise UnavailableConfiguration("Resolved policy differs from Runtime configuration")
        if request.config.model != runtime_model_configuration():
            raise UnavailableConfiguration("Requested model settings differ from Runtime environment")
        from examples.run_agent_mcp_e2e import AgentCaseInput, execute_agent_case

        case = AgentCaseInput(**build_agent_case_kwargs(request.case))
        if self._running:
            raise UnavailableConfiguration("Runtime backend requires serial execution")
        self._running = True
        try:
            directory = self.private_root / f"trial-{uuid4()}"
            directory.mkdir(parents=True, exist_ok=False, mode=0o700)
            runtime_directory = directory / "runtime"
            observation.unknown_reasons["sdk_calls"] = "runtime_invocation_trace_not_yet_validated"
            try:
                with (
                    (directory / "runtime.log").open("w", encoding="utf-8") as log,
                    redirect_stdout(log), redirect_stderr(log),
                ):
                    # MCP sessions and the portal must share the same event loop.
                    async with BlockingPortal() as portal:
                        raw = await execute_agent_case(
                            portal, runtime_directory, request.config.condition, case,
                            trial_run_id=request.run_id, trial_trace_id=request.trace_id,
                            output_injection_scan=request.config.output_injection_scan,
                        )
            except asyncio.CancelledError:
                observation.unknown_reasons["runtime_partial_observation"] = (
                    "runtime_returns_observation_only_on_completion; private_artifacts_may_exist"
                )
                raise
            # Retain original private observations even if conversion rejects them.
            (directory / "runtime_observation.json").write_text(
                json.dumps(asdict(raw), ensure_ascii=False, indent=2), encoding="utf-8",
            )
            self._convert(request, observation, raw, runtime_directory)
        finally:
            self._running = False

    def _convert(self, request, obs, raw, directory):
        if (raw.trial_run_id, raw.trial_trace_id, raw.scenario_id, raw.condition) != (
            request.run_id, request.trace_id, request.case["scenario_id"], request.config.condition,
        ):
            raise ValueError("Runtime trial identity mismatch")
        if raw.policy_version is not None and raw.policy_version != request.policy.version:
            raise ValueError("Runtime policy version mismatch")
        if raw.output_injection_scan is not None and raw.output_injection_scan != request.config.output_injection_scan:
            raise ValueError("Runtime PI-T01 setting mismatch")
        expected_mode = request.policy.configuration.policy.initial_inspection_mode.value
        if raw.initial_inspection_mode is not None and raw.initial_inspection_mode != expected_mode:
            raise ValueError("Runtime initial inspection mode mismatch")
        if raw.requested_model is not None and raw.requested_model != request.config.model["name"]:
            raise ValueError("Runtime requested model mismatch")
        # Never create a fresh empty DB to stand in for missing Runtime Evidence.
        db = directory / "evidence.db"
        repository = SQLiteEvidenceRepository(db) if db.is_file() else None
        if raw.evidence_db_path is not None and Path(raw.evidence_db_path).resolve() != db.resolve():
            raise ValueError("Unexpected Runtime Evidence database")
        obs.evidence_refs = []
        obs.runtime_model_names = [turn.model for turn in raw.model_turns] or None
        obs.model_tool_selection_observed = (
            all(turn.tool_selection_observed for turn in raw.model_turns) if raw.model_turns else None
        )
        obs.candidate_trace_complete = raw.candidate_trace_complete
        obs.guard_trace_complete = raw.guard_trace_complete
        obs.output_delivered = raw.final_response_delivered_to_user
        obs.output_destination = "user" if raw.final_response_delivered_to_user is True else None
        obs.timed_out = raw.timed_out
        obs.run_status = raw.run_status
        obs.error_stage = raw.error_stage
        # Runtime uses machine codes; a generic code also avoids trusting exception text.
        obs.error_detail = "runtime_reported_error" if raw.error_type else None
        if obs.run_status == "completed" and (
            not raw.loop_completed or raw.policy_version is None or raw.requested_model is None
            or raw.output_injection_scan is None or raw.initial_inspection_mode is None
        ):
            obs.run_status = "incomplete"
        previous = {}
        for item in raw.tool_executions:
            candidate = self._candidate(item)
            if item.parent_candidate_id is not None:
                if item.parent_candidate_id not in previous:
                    raise ValueError("Runtime parent candidate is not an earlier candidate")
                candidate.parent_mcp_call_id = previous[item.parent_candidate_id].mcp_call_id
            previous[candidate.candidate_id] = candidate
            obs.candidates.append(candidate)
            obs.evidence_refs.extend(item.evidence_refs)
            # Partial candidates without Runtime IDs remain candidates, with no snapshots invented.
            if (item.run_id is None) != (item.trace_id is None):
                raise ValueError("Incomplete Runtime identity pair")
            if item.run_id is not None:
                if item.runtime_scenario_id != request.case["scenario_id"]:
                    raise ValueError("Runtime scenario mismatch")
                link = RuntimeIdentityBinding(
                    trial_run_id=request.run_id, trial_trace_id=request.trace_id,
                    scenario_id=request.case["scenario_id"], candidate_id=candidate.candidate_id,
                    runtime_run_id=item.run_id, runtime_trace_id=item.trace_id,
                    runtime_evidence_refs=list(item.evidence_refs),
                    link_evidence_ref=f"evaluation-runtime-link-{uuid4()}",
                )
                # Retain returned facts even if subsequent SQLite validation fails.
                # An unpersisted/unverified link cannot authorize Evidence reuse.
                obs.runtime_bindings.append(link)
                obs.evidence_refs.append(link.link_evidence_ref)
                events = repository.list_events_by_run(item.run_id) if repository else []
                if set(item.evidence_refs) != {event.event_id for event in events}:
                    raise ValueError("Runtime Evidence inventory mismatch")
                if not runtime_event_group_matches(
                    events, item.run_id, item.trace_id, request.case["scenario_id"],
                ):
                    raise ValueError("Runtime Evidence identity mismatch")
                if any(event.event_id in self.events for event in events):
                    raise ValueError("Runtime Evidence ID reused across trials")
                for event in events:
                    self.events[event.event_id] = event
                if repository:
                    event = SecurityEvent(
                        event_id=link.link_evidence_ref, run_id=request.run_id, trace_id=request.trace_id,
                        scenario_id=request.case["scenario_id"], event_type="EVALUATION_RUNTIME_LINK",
                        payload=link.model_dump(mode="json", exclude={"link_evidence_ref"}),
                    )
                    repository.save_event(event)
                    self.events[event.event_id] = event
        obs.unknown_reasons.update({
            "payload_exposure_refs": "runtime_has_no_explicit_exposure_event",
            "model_response_refs": (
                "private_response_available_but_no_model_response_evidence_event"
                if raw.final_response is not None else "runtime_final_response_not_observed"
            ),
            "attack_objective_achieved": "semantic_judgment_not_performed",
            "legitimate_task_success": "semantic_judgment_not_performed",
        })
        self._record_returned_telemetry(request, obs, raw, directory)

    def _record_returned_telemetry(self, request, obs, raw, directory):
        # Do not equate missing telemetry on interrupted runs with zero calls.
        # The complete private raw observation remains available for diagnostics.
        if obs.run_status != "completed" or not raw.loop_completed or not raw.candidate_trace_complete:
            return
        source_hash = sha256((directory.parent / "runtime_observation.json").read_bytes())

        def record(kind, payload):
            event = SecurityEvent(
                event_id=f"evaluation-observation-{uuid4()}",
                run_id=request.run_id, trace_id=request.trace_id,
                scenario_id=request.case["scenario_id"], event_type=kind,
                payload={
                    "source": "evaluation_ingestion_of_runtime_observation",
                    "source_observation_sha256": source_hash,
                    "sample_id": request.case["sample_id"],
                    "mapped_case_sha256": record_sha256(request.case),
                    "policy_version": request.policy.version,
                    **payload,
                },
            )
            # The CLI persists the replay index; the original Runtime DB is not
            # rewritten to pretend these were native Runtime events.
            self.events[event.event_id] = event
            obs.evidence_refs.append(event.event_id)
            return event.event_id

        calls = self._validated_sdk_calls(raw, obs)
        if calls is not None:
            obs.sdk_calls = []
            for call, tool_name in calls:
                call.evidence_ref = record("SDK_INVOCATION", {
                    "method": call.method, "timestamp": call.timestamp.isoformat(),
                    "candidate_id": call.candidate_id, "mcp_call_id": call.mcp_call_id,
                    "tool_name": tool_name, "invoked": True,
                })
                obs.sdk_calls.append(call)
        else:
            obs.unknown_reasons["sdk_calls"] = "runtime_invocation_trace_missing_or_inconsistent"

        # Final generation is not user delivery. Require corroboration by the
        # recorded terminal model turn, not merely a nonempty text field.
        if raw.model_turns and obs.evidence_refs:
            last = raw.model_turns[-1]
            if (
                isinstance(raw.final_response, str) and raw.final_response.strip()
                and last.response_text == raw.final_response
                and last.model and last.tool_selection_observed is True
                and not last.tool_calls and last.selection_error is None
            ):
                obs.model_response_refs = [record("MODEL_RESPONSE", {
                    "actual_model": True, "final": True, "text": raw.final_response,
                    "model": last.model, "model_turn": last.turn,
                    "delivered_to_user": raw.final_response_delivered_to_user,
                })]
            elif raw.final_response is not None:
                obs.unknown_reasons["model_response_refs"] = "terminal_model_response_not_corroborated"

    @staticmethod
    def _validated_sdk_calls(raw, obs):
        """Accept only a coherent observed invocation trace; no inferred calls."""
        records = getattr(raw, "sdk_calls", None)
        if not isinstance(records, list) or not records:
            return None
        candidates = {c.candidate_id: c for c in obs.candidates}
        counts = dict.fromkeys(candidates, 0)
        result = []
        discovered = False
        try:
            for item in records:
                if item["invoked"] is not True:
                    return None
                method = item["method"]
                candidate_id = item["candidate_id"]
                call_id = item["mcp_call_id"]
                tool_name = item["tool_name"]
                stamp = datetime.fromisoformat(item["timestamp"])
                if stamp.utcoffset() is None:
                    return None
                if method == "tools/list":
                    if candidate_id is not None or call_id is not None or tool_name is not None:
                        return None
                    discovered = True
                elif method == "tools/call":
                    candidate = candidates.get(candidate_id)
                    if not discovered or candidate is None or candidate.tool_name != tool_name:
                        return None
                    if call_id is not None and call_id != candidate.mcp_call_id:
                        return None
                    counts[candidate_id] += 1
                else:
                    return None
                result.append((SDKCall(
                    method=method, timestamp=stamp, candidate_id=candidate_id,
                    mcp_call_id=call_id,
                ), tool_name))
        except (KeyError, TypeError, ValueError, AttributeError):
            return None
        times = [call.timestamp for call, _ in result]
        if not discovered or times != sorted(times) or any(
            candidate.sdk_call_count != counts[cid] for cid, candidate in candidates.items()
        ):
            return None
        return result

    @staticmethod
    def _candidate(item):
        decision = (
            SecurityDecision.model_validate(item.security_decision_snapshot)
            if item.security_decision_snapshot is not None else None
        )
        results = [SecurityResult.model_validate(row) for row in item.security_result_snapshots]
        if item.tool_name not in {"demo/read_file", "demo/send_email"}:
            raise ValueError("Unexpected Runtime candidate target")
        action = ToolAction(
            server_name="demo", tool_name=item.tool_name, arguments=item.tool_arguments,
        ) if item.tool_arguments is not None else None
        # A Runtime return time is NOT a model selection timestamp. Label it explicitly.
        candidate = CandidateObservation(
            candidate_id=item.candidate_id, timestamp=datetime.now(UTC),
            timestamp_scope="evaluation_ingestion",
            model_tool_call_id=item.model_tool_call_id, parent_candidate_id=item.parent_candidate_id,
            mcp_call_id=item.runtime_tool_call_id,
            server_name="demo", tool_name=item.tool_name, candidate_source="model",
            model_selected_tool=action,
            # A recorded selection does not establish a submitted Runtime request on failure.
            requested_tool=action if item.run_id is not None else None,
            security_decision=decision, guard_results=results or None,
            sdk_call_count=item.sdk_call_count, server_tool_body_counts=item.server_call_counts,
            tool_executed=item.tool_executed, output_allowed=item.output_allowed,
            output_delivered=item.output_delivered, output_destination=item.output_destination,
            evidence_refs=list(item.evidence_refs),
        )
        candidate.unknown_reasons.update({
            "call_count": "server_counter_measures_tool_body_entry_not_request_receipt",
            "guard_decision": "aggregate_security_decision_includes_tool_policy",
            "tool_policy_decision": "no_separate_runtime_tool_policy_decision",
            "pre_tool_block": "execution_boundary_attribution_not_verified",
            "post_tool_output_block": "output_guard_attribution_not_verified",
        })
        return candidate
