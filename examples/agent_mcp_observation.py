"""Internal observations for the actual Agent-MCP execution path."""

import json
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any


def observe_tool_calls(calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    observations = []

    for index, call in enumerate(calls):
        function = call.get("function") or {}
        raw_arguments = function.get("arguments")

        arguments_valid = False

        if isinstance(raw_arguments, str):
            try:
                arguments = json.loads(raw_arguments)
                arguments_valid = isinstance(arguments, dict)
            except json.JSONDecodeError:
                pass

        observations.append({
            "index": index,
            "model_tool_call_id": call.get("id"),
            "provider_tool_name": function.get("name"),
            "arguments_valid": arguments_valid,
        })

    return observations


def selection_error(observations: list[dict[str, Any]]) -> str | None:
    if len(observations) > 1:
        return "MULTIPLE_TOOL_CALLS_UNSUPPORTED"

    if not observations:
        return None

    selected = observations[0]

    if not selected["provider_tool_name"]:
        return "INVALID_TOOL_NAME"

    if not selected["model_tool_call_id"]:
        return "MISSING_MODEL_TOOL_CALL_ID"

    if not selected["arguments_valid"]:
        return "INVALID_TOOL_ARGUMENTS"

    return None


@dataclass
class ModelTurnObservation:
    turn: int
    model: str | None = None
    elapsed_seconds: float | None = None
    finish_reason: str | None = None
    tool_selection_observed: bool = False
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    response_text_chars: int | None = None
    response_text: str | None = field(default=None, repr=False)
    selection_error: str | None = None


@dataclass
class ToolExecutionObservation:
    model_turn: int
    provider_tool_name: str
    tool_name: str
    model_tool_call_id: str | None = None

    tool_arguments: dict[str, Any] | None = field(
        default=None, repr=False
    )

    candidate_id: str | None = None
    parent_candidate_id: str | None = None

    forward_output: Any = field(default=None, repr=False)

    runtime_tool_call_id: str | None = None
    run_id: str | None = None
    trace_id: str | None = None

    runtime_status: str | None = None
    security_decision: str | None = None

    security_decision_snapshot: dict[str, Any] | None = field(
        default=None, repr=False
    )
    security_result_snapshots: list[dict[str, Any]] = field(
        default_factory=list, repr=False
    )
    execution_state: str | None = None

    sdk_call_count: int | None = None
    server_call_counts: dict[str, int] | None = None

    tool_executed: bool | None = None
    output_allowed: bool | None = None
    output_delivered: bool | None = None
    output_destination: str | None = None
    output_queued: bool = False
    blocked_notice_queued: bool = False
    blocked_notice_delivered: bool | None = None
    followup_model_turn: int | None = None

    runtime_error_codes: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    evidence_event_types: dict[str, str] = field(default_factory=dict)
    evidence_identity_verified: bool | None = None
    runtime_scenario_id: str | None = None


    def record_runtime_result(self, result: Any) -> None:
        self.run_id = result.identity.run_id
        self.trace_id = result.identity.trace_id
        self.runtime_status = result.run_status.value

        self.security_decision = (
            result.decision.decision.value
            if result.decision is not None
            else None
        )

        self.output_allowed = result.output_allowed
        self.forward_output = deepcopy(result.forward_output)

        self.runtime_error_codes = [
            error.code for error in result.errors
        ]

        if result.execution is not None:
            self.runtime_tool_call_id = result.execution.tool_call_id
            self.execution_state = result.execution.execution_state.value
            self.tool_executed = result.execution.executed


    def record_evidence(self, events: list[Any]) -> None:
        if self.run_id is None or self.trace_id is None:
            raise ValueError("Runtime identity is not available")

        self.evidence_identity_verified = None
        self.evidence_refs = []
        self.evidence_event_types = {}
        self.security_result_snapshots = []

        if not events:
            return

        if any(
            event.run_id != self.run_id
            or event.trace_id != self.trace_id
            for event in events
        ):
            self.evidence_identity_verified = False
            raise ValueError("Evidence identity mismatch")

        expected_policy = (
            self.security_decision_snapshot or {}
        ).get("policy_version")

        for event in events:
            scenario_id = getattr(event, "scenario_id", None)

            if (
                self.runtime_scenario_id is not None
                and scenario_id is not None
                and scenario_id != self.runtime_scenario_id
            ):
                self.evidence_identity_verified = False
                raise ValueError("Evidence scenario identity mismatch")

            payload = event.payload

            if not isinstance(payload, dict):
                continue

            expected_fields = {
                "run_id": self.run_id,
                "trace_id": self.trace_id,
                "scenario_id": self.runtime_scenario_id,
            }

            for key, expected in expected_fields.items():
                if (
                    expected is not None
                    and payload.get(key) is not None
                    and payload[key] != expected
                ):
                    self.evidence_identity_verified = False
                    raise ValueError("Evidence payload identity mismatch")

            if (
                event.event_type == "SECURITY_DECISION"
                and expected_policy is not None
                and payload.get("policy_version") != expected_policy
            ):
                self.evidence_identity_verified = False
                raise ValueError("Evidence policy version mismatch")

        refs = [event.event_id for event in events]

        if len(refs) != len(set(refs)):
            self.evidence_identity_verified = False
            raise ValueError("Duplicate evidence event ID")

        self.evidence_refs = refs
        self.evidence_event_types = {
            event.event_id: event.event_type
            for event in events
        }

        self.security_result_snapshots = [
            deepcopy(event.payload)
            for event in events
            if event.event_type == "SECURITY_RESULT"
        ]

        self.evidence_identity_verified = True


@dataclass
class AgentRunObservation:
    scenario_id: str
    condition: str
    trial_run_id: str | None = None
    trial_trace_id: str | None = None
    evidence_db_path: str | None = field(default=None, repr=False)

    requested_model: str | None = None
    policy_version: str | None = None

    run_status: str = "incomplete"
    loop_completed: bool = False
    legacy_verification_passed: bool | None = None
    final_response: str | None = field(default=None, repr=False)
    final_response_delivered_to_user: bool | None = None
    timed_out: bool = False

    model_turns: list[ModelTurnObservation] = field(
        default_factory=list
    )

    tool_executions: list[ToolExecutionObservation] = field(
        default_factory=list
    )

    error_stage: str | None = None
    error_type: str | None = None

    candidate_trace_complete: bool = False
    guard_trace_complete: bool = False

    def record_model_turn(
        self,
        turn: int,
        model: str | None,
        diagnostics: dict[str, Any],
        response_text: str | None = None,
    ) -> ModelTurnObservation:
        calls = diagnostics.get("tool_call_observations")

        observation = ModelTurnObservation(
            turn=turn,
            model=model,
            elapsed_seconds=diagnostics.get("elapsed_seconds"),
            finish_reason=diagnostics.get("finish_reason"),
            tool_selection_observed=calls is not None,
            tool_calls=[
                dict(call) for call in calls
            ] if calls is not None else [],
            response_text_chars=diagnostics.get("text_chars"),
            response_text=response_text,
            selection_error=(
                selection_error(calls)
                if calls is not None
                else "MODEL_SELECTION_OBSERVATION_MISSING"
            ),
        )

        self.model_turns.append(observation)
        return observation

    def record_tool_candidate(
        self,
        model_turn: int,
        provider_tool_name: str,
        tool_name: str,
        model_tool_call_id: str | None,
        tool_arguments: dict[str, Any] | None = None,
    ) -> ToolExecutionObservation:
        observation = ToolExecutionObservation(
            model_turn=model_turn,
            provider_tool_name=provider_tool_name,
            tool_name=tool_name,
            model_tool_call_id=model_tool_call_id,
            tool_arguments=deepcopy(tool_arguments),
        )

        observation.candidate_id = (
            f"candidate-{len(self.tool_executions) + 1}"
        )

        if self.tool_executions:
            observation.parent_candidate_id = (
                self.tool_executions[-1].candidate_id
            )

        self.tool_executions.append(observation)
        return observation

    def finalize_candidate_trace(self) -> None:
        """Verify observed model selections against recorded candidates."""
        self.candidate_trace_complete = False

        if (
            self.run_status != "completed"
            or not self.loop_completed
            or not self.model_turns
        ):
            return

        expected = []

        for index, turn in enumerate(self.model_turns, start=1):
            if (
                turn.turn != index
                or not turn.tool_selection_observed
                or turn.selection_error is not None
            ):
                return

            for call in turn.tool_calls:
                expected.append((
                    turn.turn,
                    call["model_tool_call_id"],
                    call["provider_tool_name"],
                ))

        actual = [
            (
                candidate.model_turn,
                candidate.model_tool_call_id,
                candidate.provider_tool_name,
            )
            for candidate in self.tool_executions
        ]

        candidate_ids = [
            candidate.candidate_id
            for candidate in self.tool_executions
        ]

        if any(not item for item in candidate_ids):
            return

        if len(candidate_ids) != len(set(candidate_ids)):
            return

        if self.model_turns[-1].tool_calls:
            return

        self.candidate_trace_complete = expected == actual

    def finalize_guard_trace(self) -> None:
        """Conservatively verify observed A/B/C guard execution paths."""
        self.guard_trace_complete = False

        if (
            not self.candidate_trace_complete
            or not self.tool_executions
            or self.condition not in {"A", "B", "C"}
        ):
            return

        expected = ["INPUT", "CONTEXT", "TOOL", "OUTPUT"]

        for candidate in self.tool_executions:
            if (
                candidate.runtime_status != "COMPLETED"
                or candidate.runtime_error_codes
                or candidate.evidence_identity_verified is not True
                or candidate.security_decision_snapshot is None
                or "SECURITY_DECISION"
                not in candidate.evidence_event_types.values()
                or "EXECUTION_RESULT"
                not in candidate.evidence_event_types.values()
            ):
                return

            snapshots = candidate.security_result_snapshots

            if any(not isinstance(item, dict) for item in snapshots):
                return

            stages = [
                str(item.get("stage", "")).upper()
                for item in snapshots
            ]

            if self.condition == "A":
                if stages:
                    return
                continue

            if candidate.execution_state == "BLOCKED":
                if (
                    candidate.security_decision != "BLOCK"
                    or candidate.tool_executed is not False
                    or candidate.sdk_call_count != 0
                    or candidate.output_allowed is not False
                    or not stages
                    or len(stages) > 3
                    or stages != expected[:len(stages)]
                ):
                    return

                # Require direct evidence of an early Guard BLOCK.
                # Other aggregate blocking paths remain unverified.
                if str(
                    snapshots[-1].get("decision", "")
                ).upper() != "BLOCK":
                    return

            elif candidate.execution_state == "EXECUTED":
                if (
                    candidate.tool_executed is not True
                    or candidate.sdk_call_count != 1
                ):
                    return

                valid_paths = [expected]

                if self.condition == "C":
                    valid_paths.append(expected + ["OUTPUT"])

                if stages not in valid_paths:
                    return

            else:
                return

        self.guard_trace_complete = True

    def mark_completed(self) -> None:
        self.run_status = "completed"
        self.loop_completed = True

    def mark_error(
        self,
        stage: str,
        error_type: str,
        *,
        timed_out: bool = False,
    ) -> None:
        self.run_status = "timeout" if timed_out else "error"
        self.loop_completed = False
        self.timed_out = timed_out
        self.error_stage = stage
        self.error_type = error_type



def public_summary(observation: AgentRunObservation) -> dict[str, Any]:
    """Return an allowlisted summary without raw execution content."""

    return {
        "schema_version": "0.1.0",
        "scenario_id": observation.scenario_id,
        "condition": observation.condition,
        "trial_run_id": observation.trial_run_id,
        "trial_trace_id": observation.trial_trace_id,
        "requested_model": observation.requested_model,
        "policy_version": observation.policy_version,
        "run_status": observation.run_status,
        "loop_completed": observation.loop_completed,
        "timed_out": observation.timed_out,
        "error_stage": observation.error_stage,
        "error_type": observation.error_type,
        "candidate_trace_complete": observation.candidate_trace_complete,
        "guard_trace_complete": observation.guard_trace_complete,
        "final_response_observed": (
            observation.final_response is not None
        ),
        "final_response_delivered_to_user": (
            observation.final_response_delivered_to_user
        ),
        "model_turns": [
            {
                "turn": turn.turn,
                "model": turn.model,
                "elapsed_seconds": turn.elapsed_seconds,
                "finish_reason": turn.finish_reason,
                "tool_selection_observed": turn.tool_selection_observed,
                "tool_call_count": (
                    len(turn.tool_calls)
                    if turn.tool_selection_observed else None
                ),
                "response_text_chars": turn.response_text_chars,
                "selection_error": turn.selection_error,
            }
            for turn in observation.model_turns
        ],
        "tool_executions": [
            {
                "candidate_id": item.candidate_id,
                "parent_candidate_id": item.parent_candidate_id,
                "model_turn": item.model_turn,
                "tool_name": item.tool_name,
                "runtime_tool_call_id": item.runtime_tool_call_id,
                "run_id": item.run_id,
                "trace_id": item.trace_id,
                "runtime_scenario_id": item.runtime_scenario_id,
                "runtime_status": item.runtime_status,
                "security_decision": item.security_decision,
                "execution_state": item.execution_state,
                "sdk_call_count": item.sdk_call_count,
                "server_call_counts": item.server_call_counts,
                "tool_executed": item.tool_executed,
                "output_allowed": item.output_allowed,
                "output_queued": item.output_queued,
                "blocked_notice_queued": item.blocked_notice_queued,
                "blocked_notice_delivered": (
                    item.blocked_notice_delivered
                ),
                "output_delivered": item.output_delivered,
                "output_destination": item.output_destination,
                "followup_model_turn": item.followup_model_turn,
                "runtime_error_codes": item.runtime_error_codes,
                "evidence_refs": item.evidence_refs,
                "evidence_event_types": item.evidence_event_types,
                "evidence_identity_verified": (
                    item.evidence_identity_verified
                ),
            }
            for item in observation.tool_executions
        ],
    }
