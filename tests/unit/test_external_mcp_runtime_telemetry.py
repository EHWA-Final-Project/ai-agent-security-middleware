"""Offline contracts for returned Runtime telemetry, never live-model results."""
from datetime import UTC, datetime, timedelta

import pytest

from evaluation.external_mcp_evidence import EvidenceView
from evaluation.external_mcp_judges import judge_trial
from evaluation.external_mcp_metrics import aggregate_external
from tests.unit import test_external_mcp_runtime_backend as runtime_tests

setup = runtime_tests.setup


def install_telemetry(monkeypatch, setup, *, mode="valid"):
    from examples import run_agent_mcp_e2e as runtime

    runtime_tests.install_runtime(monkeypatch, setup)
    original = runtime.execute_agent_case

    async def observed(*args, **kwargs):
        raw = await original(*args, **kwargs)
        start = datetime.now(UTC)
        raw.sdk_calls = [
            {"method": "tools/list", "timestamp": start.isoformat(),
             "candidate_id": None, "mcp_call_id": None, "tool_name": None, "invoked": True},
            {"method": "tools/call", "timestamp": (start + timedelta(milliseconds=1)).isoformat(),
             "candidate_id": "candidate-1", "mcp_call_id": None,
             "tool_name": "demo/read_file", "invoked": True},
        ]
        if mode == "missing":
            raw.sdk_calls = []
        elif mode == "count":
            raw.sdk_calls.pop()
        elif mode == "foreign":
            raw.sdk_calls[1]["candidate_id"] = "foreign"
        elif mode == "wrong_tool":
            raw.sdk_calls[1]["tool_name"] = "demo/send_email"
        elif mode == "naive_time":
            raw.sdk_calls[1]["timestamp"] = start.replace(tzinfo=None).isoformat()
        elif mode == "reordered":
            raw.sdk_calls[1]["timestamp"] = (start - timedelta(seconds=1)).isoformat()
        elif mode == "uninvoked":
            raw.sdk_calls[1]["invoked"] = False
        elif mode == "response_mismatch":
            raw.final_response = "different from terminal turn"
        return raw

    monkeypatch.setattr(runtime, "execute_agent_case", observed)


def test_sdk_and_final_response_keep_distinct_observations(setup, monkeypatch):
    install_telemetry(monkeypatch, setup)
    trial = runtime_tests.run(setup)
    events = setup[3].events
    assert trial.evidence_validated is True
    assert trial.observation.run_status == "completed"
    view = EvidenceView(trial, events.get)
    assert view.base_reason() is None
    assert [c.method for c in trial.observation.sdk_calls] == ["tools/list", "tools/call"]
    sdk = trial.observation.sdk_calls[1]
    assert sdk.mcp_call_id is None
    event = view.get(sdk.evidence_ref, "SDK_INVOCATION")
    assert event.payload["timestamp"] == sdk.timestamp.isoformat()
    assert event.payload["source_observation_sha256"]
    response = view.get(trial.observation.model_response_refs[0], "MODEL_RESPONSE")
    assert response.payload["text"] == "42"
    assert response.payload["delivered_to_user"] is None
    judged = judge_trial(trial, setup[0], events.get)
    assert judged.observation.semantic_outcomes.task.value is None
    assert judged.observation.semantic_outcomes.task.reason == "final_response_delivery_unverified"
    rates = aggregate_external([judged], events.get)["groups"][0]["rates"]
    assert rates["actual_sdk_execution"]["numerator"] == 1
    assert rates["actual_sdk_execution"]["denominator"] == 1
    assert rates["tsr_benign"]["denominator"] == 0


@pytest.mark.parametrize("mode", ["missing", "count", "foreign", "wrong_tool", "naive_time", "reordered", "uninvoked"])
def test_missing_or_inconsistent_sdk_trace_stays_unknown(setup, monkeypatch, mode):
    install_telemetry(monkeypatch, setup, mode=mode)
    trial = runtime_tests.run(setup)
    assert trial.observation.sdk_calls is None
    assert not any(e.event_type == "SDK_INVOCATION" for e in setup[3].events.values())


def test_uncorroborated_final_response_not_promoted(setup, monkeypatch):
    install_telemetry(monkeypatch, setup, mode="response_mismatch")
    trial = runtime_tests.run(setup)
    assert trial.observation.model_response_refs is None
    assert not any(e.event_type == "MODEL_RESPONSE" for e in setup[3].events.values())
