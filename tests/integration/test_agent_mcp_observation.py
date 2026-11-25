import pytest
from agent_mcp_observation import observe_tool_calls, selection_error


def make_call(
    name="demo__read_file",
    arguments='{"path": "docs/test.txt"}',
    call_id="call_test",
):
    return {
        "id": call_id,
        "function": {
            "name": name,
            "arguments": arguments,
        },
    }


def test_no_tool_selection():
    observations = observe_tool_calls([])

    assert observations == []
    assert selection_error(observations) is None


def test_single_valid_tool_selection():
    observations = observe_tool_calls([make_call()])

    assert observations == [{
        "index": 0,
        "model_tool_call_id": "call_test",
        "provider_tool_name": "demo__read_file",
        "arguments_valid": True,
    }]

    assert selection_error(observations) is None


def test_multiple_tool_selections_are_preserved():
    observations = observe_tool_calls([
        make_call(call_id="call_1"),
        make_call(
            name="demo__send_email",
            call_id="call_2",
        ),
    ])

    assert len(observations) == 2
    assert observations[0]["model_tool_call_id"] == "call_1"
    assert observations[1]["model_tool_call_id"] == "call_2"

    assert (
        selection_error(observations)
        == "MULTIPLE_TOOL_CALLS_UNSUPPORTED"
    )


@pytest.mark.parametrize(
    "arguments",
    ["invalid-json", "[]", "null", "", None, "123"],
)
def test_invalid_arguments(arguments):
    observations = observe_tool_calls([
        make_call(arguments=arguments)
    ])

    assert observations[0]["arguments_valid"] is False
    assert selection_error(observations) == "INVALID_TOOL_ARGUMENTS"


def test_missing_tool_name():
    observations = observe_tool_calls([make_call(name="")])

    assert selection_error(observations) == "INVALID_TOOL_NAME"


def test_missing_model_call_id():
    observations = observe_tool_calls([make_call(call_id="")])

    assert selection_error(observations) == "MISSING_MODEL_TOOL_CALL_ID"


def test_raw_arguments_not_stored():
    observations = observe_tool_calls([
        make_call(arguments='{"body": "synthetic-private-data"}')
    ])

    assert "synthetic-private-data" not in str(observations)


def test_agent_observation_initial_state():
    from agent_mcp_observation import AgentRunObservation

    observation = AgentRunObservation(
        scenario_id="external-test",
        condition="C",
    )

    assert observation.run_status == "incomplete"
    assert observation.loop_completed is False
    assert observation.model_turns == []
    assert observation.candidate_trace_complete is False
    assert observation.guard_trace_complete is False


def test_agent_observation_records_model_turn():
    from agent_mcp_observation import AgentRunObservation

    observation = AgentRunObservation("external-test", "C")

    turn = observation.record_model_turn(
        turn=1,
        model="qwen3:8b",
        diagnostics={
            "elapsed_seconds": 1.25,
            "finish_reason": "tool_calls",
            "text_chars": 0,
            "tool_call_observations": observe_tool_calls(
                [make_call()]
            ),
        },
    )

    assert turn.turn == 1
    assert turn.model == "qwen3:8b"
    assert turn.elapsed_seconds == 1.25
    assert turn.tool_selection_observed is True
    assert len(turn.tool_calls) == 1
    assert turn.selection_error is None
    assert observation.model_turns == [turn]


def test_observed_no_selection_is_not_missing_observation():
    from agent_mcp_observation import AgentRunObservation

    observation = AgentRunObservation("external-test", "C")

    no_selection = observation.record_model_turn(
        1, "qwen3:8b", {"tool_call_observations": []}
    )

    missing = observation.record_model_turn(
        2, "qwen3:8b", {}
    )

    assert no_selection.tool_selection_observed is True
    assert no_selection.tool_calls == []
    assert no_selection.selection_error is None

    assert missing.tool_selection_observed is False
    assert (
        missing.selection_error
        == "MODEL_SELECTION_OBSERVATION_MISSING"
    )


def test_agent_observation_completion():
    from agent_mcp_observation import AgentRunObservation

    observation = AgentRunObservation("external-test", "C")
    observation.mark_completed()

    assert observation.run_status == "completed"
    assert observation.loop_completed is True

    # Loop completion does not prove evidence completeness.
    assert observation.candidate_trace_complete is False
    assert observation.guard_trace_complete is False


@pytest.mark.parametrize("timed_out", [False, True])
def test_agent_observation_preserves_partial_results(timed_out):
    from agent_mcp_observation import AgentRunObservation

    observation = AgentRunObservation("external-test", "C")

    observation.record_model_turn(
        1,
        "qwen3:8b",
        {"tool_call_observations": observe_tool_calls([make_call()])},
    )

    observation.mark_error(
        "model_request",
        "TimeoutError" if timed_out else "RuntimeError",
        timed_out=timed_out,
    )

    assert observation.run_status == (
        "timeout" if timed_out else "error"
    )
    assert observation.timed_out is timed_out
    assert observation.loop_completed is False
    assert observation.error_stage == "model_request"
    assert len(observation.model_turns) == 1
    assert len(observation.model_turns[0].tool_calls) == 1


def test_agent_observations_are_independent():
    from agent_mcp_observation import AgentRunObservation

    first = AgentRunObservation("first", "B")
    second = AgentRunObservation("second", "C")

    first.record_model_turn(
        1, "qwen3:8b", {"tool_call_observations": []}
    )

    assert len(first.model_turns) == 1
    assert second.model_turns == []


def test_tool_candidate_initial_state():
    from agent_mcp_observation import AgentRunObservation

    observation = AgentRunObservation("external-test", "C")

    candidate = observation.record_tool_candidate(
        model_turn=1,
        provider_tool_name="demo__read_file",
        tool_name="demo/read_file",
        model_tool_call_id="call_test",
    )

    assert candidate.model_turn == 1
    assert candidate.tool_name == "demo/read_file"
    assert candidate.model_tool_call_id == "call_test"

    assert candidate.sdk_call_count is None
    assert candidate.server_call_counts is None
    assert candidate.tool_executed is None
    assert candidate.output_allowed is None
    assert candidate.output_delivered is None

    assert observation.tool_executions == [candidate]


def test_tool_observation_distinguishes_zero_from_unknown():
    from agent_mcp_observation import AgentRunObservation

    observation = AgentRunObservation("external-test", "C")

    candidate = observation.record_tool_candidate(
        1, "demo__send_email", "demo/send_email", "call_test"
    )

    assert candidate.sdk_call_count is None

    candidate.sdk_call_count = 0
    candidate.server_call_counts = {
        "read_file": 0,
        "send_email": 0,
    }
    candidate.tool_executed = False
    candidate.output_allowed = False

    assert candidate.sdk_call_count == 0
    assert candidate.tool_executed is False
    assert candidate.output_allowed is False

    # Delivery has not yet been observed.
    assert candidate.output_delivered is None


def test_tool_observations_preserve_candidate_order():
    from agent_mcp_observation import AgentRunObservation

    observation = AgentRunObservation("external-test", "C")

    first = observation.record_tool_candidate(
        1, "demo__read_file", "demo/read_file", "call_1"
    )

    second = observation.record_tool_candidate(
        2, "demo__send_email", "demo/send_email", "call_2"
    )

    assert observation.tool_executions == [first, second]
    assert first.evidence_refs == []
    assert second.evidence_refs == []

    first.evidence_refs.append("event-test")

    assert second.evidence_refs == []


def test_partial_tool_observation_survives_error():
    from agent_mcp_observation import AgentRunObservation

    observation = AgentRunObservation("external-test", "C")

    candidate = observation.record_tool_candidate(
        1, "demo__read_file", "demo/read_file", "call_test"
    )

    candidate.sdk_call_count = 1

    observation.mark_error(
        "runtime_execution",
        "TimeoutError",
        timed_out=True,
    )

    assert observation.run_status == "timeout"
    assert observation.tool_executions == [candidate]
    assert candidate.sdk_call_count == 1
    assert candidate.tool_executed is None
    assert observation.candidate_trace_complete is False


@pytest.mark.parametrize(
    "decision, execution_state, executed, output_allowed",
    [
        ("ALLOW", "EXECUTED", True, True),
        ("BLOCK", "BLOCKED", False, False),
        ("BLOCK", "EXECUTED", True, False),
    ],
)
def test_record_runtime_result(
    decision,
    execution_state,
    executed,
    output_allowed,
):
    from types import SimpleNamespace

    from agent_mcp_observation import AgentRunObservation

    observation = AgentRunObservation("external-test", "C")

    candidate = observation.record_tool_candidate(
        1, "demo__read_file", "demo/read_file", "call_test"
    )

    result = SimpleNamespace(
        identity=SimpleNamespace(
            run_id="run-test",
            trace_id="trace-test",
        ),
        run_status=SimpleNamespace(value="COMPLETED"),
        decision=SimpleNamespace(
            decision=SimpleNamespace(value=decision),
        ),
        execution=SimpleNamespace(
            tool_call_id="tool-test",
            execution_state=SimpleNamespace(
                value=execution_state
            ),
            executed=executed,
        ),
        output_allowed=output_allowed,
        forward_output={"content": "test"} if output_allowed else None,
        errors=[],
    )

    candidate.record_runtime_result(result)

    assert candidate.run_id == "run-test"
    assert candidate.trace_id == "trace-test"
    assert candidate.runtime_tool_call_id == "tool-test"
    assert candidate.runtime_status == "COMPLETED"
    assert candidate.security_decision == decision
    assert candidate.execution_state == execution_state
    assert candidate.tool_executed is executed
    assert candidate.output_allowed is output_allowed

    # Delivery must be observed separately.
    assert candidate.output_delivered is None


def test_record_failed_runtime_result():
    from types import SimpleNamespace

    from agent_mcp_observation import AgentRunObservation

    observation = AgentRunObservation("external-test", "C")

    candidate = observation.record_tool_candidate(
        1, "demo__read_file", "demo/read_file", "call_test"
    )

    result = SimpleNamespace(
        identity=SimpleNamespace(
            run_id="run-test",
            trace_id="trace-test",
        ),
        run_status=SimpleNamespace(value="FAILED"),
        decision=None,
        execution=SimpleNamespace(
            tool_call_id="tool-test",
            execution_state=SimpleNamespace(value="FAILED"),
            executed=True,
        ),
        output_allowed=False,
        forward_output=None,
        errors=[
            SimpleNamespace(code="TOOL_EXECUTION_ERROR")
        ],
    )

    candidate.record_runtime_result(result)

    assert candidate.runtime_status == "FAILED"
    assert candidate.security_decision is None
    assert candidate.execution_state == "FAILED"
    assert candidate.tool_executed is True
    assert candidate.output_allowed is False
    assert candidate.runtime_error_codes == [
        "TOOL_EXECUTION_ERROR"
    ]


def test_record_runtime_without_execution():
    from types import SimpleNamespace

    from agent_mcp_observation import AgentRunObservation

    observation = AgentRunObservation("external-test", "C")

    candidate = observation.record_tool_candidate(
        1, "demo__read_file", "demo/read_file", "call_test"
    )

    result = SimpleNamespace(
        identity=SimpleNamespace(
            run_id="run-test",
            trace_id="trace-test",
        ),
        run_status=SimpleNamespace(value="FAILED"),
        decision=None,
        execution=None,
        output_allowed=False,
        forward_output=None,
        errors=[],
    )

    candidate.record_runtime_result(result)

    assert candidate.tool_executed is None
    assert candidate.execution_state is None
    assert candidate.runtime_tool_call_id is None
    assert candidate.sdk_call_count is None
    assert candidate.output_allowed is False


def test_private_tool_arguments_are_copied():
    from agent_mcp_observation import AgentRunObservation

    observation = AgentRunObservation("external-test", "C")

    arguments = {"path": "private-document.txt"}

    candidate = observation.record_tool_candidate(
        1,
        "demo__read_file",
        "demo/read_file",
        "call_test",
        tool_arguments=arguments,
    )

    arguments["path"] = "changed.txt"

    assert candidate.tool_arguments == {
        "path": "private-document.txt"
    }
    assert "private-document.txt" not in repr(candidate)


def test_private_model_response_is_preserved():
    from agent_mcp_observation import AgentRunObservation

    observation = AgentRunObservation("external-test", "C")

    turn = observation.record_model_turn(
        1,
        "qwen3:8b",
        {"tool_call_observations": []},
        response_text="private model response",
    )

    assert turn.response_text == "private model response"
    assert "private model response" not in repr(turn)


def test_output_queue_does_not_prove_delivery():
    from agent_mcp_observation import AgentRunObservation

    observation = AgentRunObservation("external-test", "C")

    candidate = observation.record_tool_candidate(
        1, "demo__read_file", "demo/read_file", "call_test"
    )

    candidate.output_allowed = True
    candidate.output_queued = True
    candidate.followup_model_turn = 2

    assert candidate.output_delivered is None
    assert candidate.output_destination is None


def test_final_response_is_not_user_delivery():
    from agent_mcp_observation import AgentRunObservation

    observation = AgentRunObservation("external-test", "C")

    observation.final_response = "private final response"
    observation.mark_completed()

    assert observation.loop_completed is True
    assert observation.final_response_delivered_to_user is None
    assert "private final response" not in repr(observation)
    assert observation.legacy_verification_passed is None


def make_evidence_candidate():
    from agent_mcp_observation import AgentRunObservation

    observation = AgentRunObservation("external-test", "C")

    candidate = observation.record_tool_candidate(
        1, "demo__read_file", "demo/read_file", "call_test"
    )

    candidate.run_id = "run-test"
    candidate.trace_id = "trace-test"

    return candidate


def make_evidence_event(
    event_id="event-1",
    event_type="SECURITY_RESULT",
    run_id="run-test",
    trace_id="trace-test",
):
    from types import SimpleNamespace

    return SimpleNamespace(
        event_id=event_id,
        event_type=event_type,
        run_id=run_id,
        trace_id=trace_id,
        payload={"private": "original evidence payload"},
    )


def test_evidence_references_preserve_original_ids():
    candidate = make_evidence_candidate()

    events = [
        make_evidence_event(),
        make_evidence_event(
            "event-2", "SECURITY_DECISION"
        ),
    ]

    candidate.record_evidence(events)

    assert candidate.evidence_refs == [
        "event-1", "event-2"
    ]
    assert candidate.evidence_event_types == {
        "event-1": "SECURITY_RESULT",
        "event-2": "SECURITY_DECISION",
    }
    assert candidate.evidence_identity_verified is True

    assert candidate.security_result_snapshots == [
        {"private": "original evidence payload"}
    ]

    events[0].payload["private"] = "changed"

    assert candidate.security_result_snapshots[0]["private"] == (
        "original evidence payload"
    )

    assert "original evidence payload" not in repr(candidate)


@pytest.mark.parametrize(
    "run_id, trace_id",
    [
        ("wrong-run", "trace-test"),
        ("run-test", "wrong-trace"),
    ],
)
def test_evidence_identity_mismatch(run_id, trace_id):
    candidate = make_evidence_candidate()

    with pytest.raises(
        ValueError, match="Evidence identity mismatch"
    ):
        candidate.record_evidence([
            make_evidence_event(
                run_id=run_id,
                trace_id=trace_id,
            )
        ])

    assert candidate.evidence_identity_verified is False
    assert candidate.evidence_refs == []


def test_empty_evidence_remains_unverified():
    candidate = make_evidence_candidate()

    candidate.record_evidence([])

    assert candidate.evidence_refs == []
    assert candidate.evidence_identity_verified is None


def test_duplicate_evidence_reference_rejected():
    candidate = make_evidence_candidate()

    with pytest.raises(
        ValueError, match="Duplicate evidence event ID"
    ):
        candidate.record_evidence([
            make_evidence_event(),
            make_evidence_event(),
        ])

    assert candidate.evidence_identity_verified is False
    assert candidate.evidence_refs == []


def test_trial_identity_mapping():
    from agent_mcp_observation import AgentRunObservation

    observation = AgentRunObservation(
        "external-test",
        "C",
        trial_run_id="trial-run",
        trial_trace_id="trial-trace",
    )

    candidate = observation.record_tool_candidate(
        1, "demo__read_file", "demo/read_file", "call_test"
    )

    candidate.run_id = "runtime-run"
    candidate.trace_id = "runtime-trace"

    assert observation.trial_run_id == "trial-run"
    assert observation.trial_trace_id == "trial-trace"
    assert candidate.run_id == "runtime-run"
    assert candidate.trace_id == "runtime-trace"


def test_candidate_sequence():
    from agent_mcp_observation import AgentRunObservation

    observation = AgentRunObservation("external-test", "C")

    first = observation.record_tool_candidate(
        1, "demo__read_file", "demo/read_file", "call_first"
    )

    second = observation.record_tool_candidate(
        2, "demo__send_email", "demo/send_email", "call_second"
    )

    assert first.candidate_id != second.candidate_id
    assert first.parent_candidate_id is None
    assert second.parent_candidate_id == first.candidate_id


def test_public_summary_excludes_private_content():
    import json

    from agent_mcp_observation import (
        AgentRunObservation,
        public_summary,
    )

    observation = AgentRunObservation("external-test", "C")

    observation.final_response = "PRIVATE_FINAL_RESPONSE"
    observation.evidence_db_path = "PRIVATE_DATABASE_PATH"

    observation.record_model_turn(
        1,
        "qwen3:8b",
        {"tool_call_observations": []},
        response_text="PRIVATE_MODEL_RESPONSE",
    )

    candidate = observation.record_tool_candidate(
        1,
        "demo__read_file",
        "demo/read_file",
        "PRIVATE_MODEL_CALL_ID",
        tool_arguments={"path": "PRIVATE_ARGUMENT"},
    )

    candidate.forward_output = {"content": "PRIVATE_OUTPUT"}

    candidate.security_decision_snapshot = {
        "reason": "PRIVATE_DECISION"
    }

    candidate.security_result_snapshots = [
        {"evidence": "PRIVATE_EVIDENCE"}
    ]

    summary = public_summary(observation)

    assert "PRIVATE_" not in json.dumps(summary)
    assert summary["final_response_observed"] is True
    assert summary["tool_executions"][0]["tool_name"] == (
        "demo/read_file"
    )


def test_public_summary_preserves_unknown_values():
    from agent_mcp_observation import (
        AgentRunObservation,
        public_summary,
    )

    observation = AgentRunObservation("external-test", "C")

    observation.record_tool_candidate(
        1, "demo__read_file", "demo/read_file", "call_test"
    )

    summary = public_summary(observation)
    candidate = summary["tool_executions"][0]

    assert candidate["sdk_call_count"] is None
    assert candidate["server_call_counts"] is None
    assert candidate["tool_executed"] is None
    assert candidate["output_delivered"] is None
    assert candidate["evidence_identity_verified"] is None
    assert summary["candidate_trace_complete"] is False
    assert summary["guard_trace_complete"] is False


def test_blocked_notice_is_not_raw_output():
    from agent_mcp_observation import (
        AgentRunObservation,
        public_summary,
    )

    observation = AgentRunObservation("external-test", "C")

    candidate = observation.record_tool_candidate(
        1, "demo__read_file", "demo/read_file", "call_test"
    )

    candidate.tool_executed = True
    candidate.output_allowed = False
    candidate.output_delivered = False
    candidate.blocked_notice_queued = True
    candidate.followup_model_turn = 2

    summary = public_summary(observation)
    item = summary["tool_executions"][0]

    assert item["tool_executed"] is True
    assert item["output_allowed"] is False
    assert item["output_queued"] is False
    assert item["output_delivered"] is False
    assert item["blocked_notice_queued"] is True
    assert item["blocked_notice_delivered"] is None


def test_blocked_notice_delivery_preserves_output_block():
    from agent_mcp_observation import (
        AgentRunObservation,
        public_summary,
    )

    observation = AgentRunObservation("external-test", "C")

    candidate = observation.record_tool_candidate(
        1, "demo__read_file", "demo/read_file", "call_test"
    )

    candidate.output_allowed = False
    candidate.output_delivered = False
    candidate.blocked_notice_queued = True
    candidate.blocked_notice_delivered = True

    item = public_summary(observation)["tool_executions"][0]

    assert item["blocked_notice_delivered"] is True
    assert item["output_delivered"] is False
    assert item["output_destination"] is None
