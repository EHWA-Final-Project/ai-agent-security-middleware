"""Regression tests for Agent-MCP policy configuration."""

import json

import anyio
import pytest
import run_agent_mcp_e2e as runner
from agent_mcp_case import AgentCaseInput
from agent_mcp_observation import AgentRunObservation, public_summary

from security.policy.conditions import load_condition


@pytest.mark.parametrize("condition_name", ["A", "B", "C", "D"])
@pytest.mark.parametrize("pit01", [None, False, True])
def test_external_case_policy_option_forwarding(
    tmp_path, monkeypatch, condition_name, pit01
):
    received = {}

    async def fake_impl(
        portal, directory, condition_name, scenario,
        case=None, observation=None, *,
        output_injection_scan=None,
    ):
        received["condition"] = condition_name
        received["pit01"] = output_injection_scan

        condition = load_condition(
            condition_name,
            output_injection_scan=output_injection_scan,
        )

        observation.policy_version = condition.policy.policy_version
        observation.output_injection_scan = (
            condition.policy.output_injection_scan
        )
        observation.initial_inspection_mode = (
            condition.policy.initial_inspection_mode.value
        )

        observation.mark_completed()
        return True

    monkeypatch.setattr(runner, "_run_e2e_impl", fake_impl)

    case = AgentCaseInput(
        scenario_id="policy-option-test",
        user_input="Read the document.",
        documents={"docs/test.txt": "Test document."},
        tool_descriptions={},
    )

    directory = tmp_path / "trial"

    async def execute():
        return await runner.execute_agent_case(
            None,
            directory,
            condition_name,
            case,
            output_injection_scan=pit01,
        )

    observation = anyio.run(execute)

    assert received["condition"] == condition_name
    assert received["pit01"] is pit01
    assert observation.run_status == "completed"

    expected = load_condition(
        condition_name,
        output_injection_scan=pit01,
    ).policy

    assert observation.policy_version == expected.policy_version
    assert observation.output_injection_scan is (
        expected.output_injection_scan
    )
    assert observation.initial_inspection_mode == (
        expected.initial_inspection_mode.value
    )

    summary = json.loads(
        (directory / "observation_summary.json").read_text()
    )

    assert summary["condition"] == condition_name
    assert summary["policy_version"] == expected.policy_version
    assert summary["output_injection_scan"] is (
        expected.output_injection_scan
    )
    assert summary["initial_inspection_mode"] == (
        expected.initial_inspection_mode.value
    )


def test_unknown_policy_settings_remain_unobserved():
    observation = AgentRunObservation("unknown-policy", "D")
    summary = public_summary(observation)

    assert summary["policy_version"] is None
    assert summary["output_injection_scan"] is None
    assert summary["initial_inspection_mode"] is None


def test_d_guard_trace_without_evidence_is_incomplete():
    observation = AgentRunObservation("d-trace-test", "D")
    observation.mark_completed()
    observation.candidate_trace_complete = True

    observation.finalize_guard_trace()

    assert observation.guard_trace_complete is False


@pytest.mark.parametrize(
    "variant, expected",
    [
        ("normal", True),
        ("pre_block", True),
        ("post_block", True),
        ("missing_guard", False),
        ("failed_guard", False),
        ("wrong_guard_name", False),
        ("wrong_run_id", False),
        ("wrong_trace_id", False),
        ("wrong_policy", False),
        ("wrong_initial_mode", False),
        ("wrong_pit01", False),
        ("missing_evidence", False),
        ("unexpected_sdk_call", False),
    ],
)
def test_d_guard_trace_paths(variant, expected):
    from types import SimpleNamespace

    observation = AgentRunObservation("d-trace-test", "D")
    observation.mark_completed()
    observation.candidate_trace_complete = True
    observation.policy_version = "v0.1.0-cond-d-adaptive"
    observation.initial_inspection_mode = "FAST"
    observation.output_injection_scan = False

    stages = ["INPUT", "CONTEXT", "TOOL", "OUTPUT"]

    if variant == "pre_block":
        stages = stages[:3]

    snapshots = [
        {
            "stage": stage,
            "guard_name": f"{stage.lower()}_guard",
            "execution_status": "SUCCESS",
            "decision": "ALLOW",
            "run_id": "runtime-run",
            "trace_id": "runtime-trace",
        }
        for stage in stages
    ]

    blocked = variant in {"pre_block", "post_block"}

    if blocked:
        snapshots[-1]["decision"] = "BLOCK"

    candidate = SimpleNamespace(
        runtime_status="COMPLETED",
        runtime_error_codes=[],
        evidence_identity_verified=True,
        run_id="runtime-run",
        trace_id="runtime-trace",
        security_decision="BLOCK" if blocked else "ALLOW",
        security_decision_snapshot={
            "policy_version": observation.policy_version,
            "decision": "BLOCK" if blocked else "ALLOW",
        },
        evidence_event_types={
            "decision-event": "SECURITY_DECISION",
            "execution-event": "EXECUTION_RESULT",
        },
        security_result_snapshots=snapshots,
        execution_state=(
            "BLOCKED" if variant == "pre_block" else "EXECUTED"
        ),
        tool_executed=variant != "pre_block",
        sdk_call_count=0 if variant == "pre_block" else 1,
        output_allowed=not blocked,
    )

    if variant == "missing_guard":
        snapshots.pop(1)
    elif variant == "failed_guard":
        snapshots[1]["execution_status"] = "ERROR"
    elif variant == "wrong_guard_name":
        snapshots[1]["guard_name"] = "unknown_guard"
    elif variant == "wrong_run_id":
        snapshots[1]["run_id"] = "wrong-run"
    elif variant == "wrong_trace_id":
        snapshots[1]["trace_id"] = "wrong-trace"
    elif variant == "wrong_policy":
        candidate.security_decision_snapshot["policy_version"] = "wrong"
    elif variant == "wrong_initial_mode":
        observation.initial_inspection_mode = "STANDARD"
    elif variant == "wrong_pit01":
        observation.output_injection_scan = True
    elif variant == "missing_evidence":
        candidate.evidence_event_types.pop("decision-event")
    elif variant == "unexpected_sdk_call":
        candidate.sdk_call_count = 2

    observation.tool_executions.append(candidate)
    observation.finalize_guard_trace()

    assert observation.guard_trace_complete is expected


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (TimeoutError(), True),
        (RuntimeError(), False),
        (ExceptionGroup("timeout", [TimeoutError()]), True),
        (
            ExceptionGroup(
                "nested",
                [
                    TimeoutError(),
                    ExceptionGroup("inner", [TimeoutError()]),
                ],
            ),
            True,
        ),
        (
            ExceptionGroup(
                "mixed",
                [TimeoutError(), RuntimeError()],
            ),
            False,
        ),
        (
            ExceptionGroup("ordinary", [RuntimeError()]),
            False,
        ),
    ],
)
def test_timeout_exception_classification(error, expected):
    from run_agent_mcp_e2e import _is_timeout_exception

    assert _is_timeout_exception(error) is expected
