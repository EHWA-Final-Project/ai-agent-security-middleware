"""Scenario linkage is inferred only from an explicit same-request anchor."""
from types import SimpleNamespace

import pytest

from evaluation.runtime_identity import runtime_event_group_matches


def event(event_id, kind, scenario, *, run="r1", trace="t1", payload=None):
    if payload is None:
        payload = {"run_id": run, "trace_id": trace}
        if scenario is not None:
            payload["scenario_id"] = scenario
    return SimpleNamespace(
        event_id=event_id, event_type=kind, scenario_id=scenario,
        run_id=run, trace_id=trace, payload=payload,
    )


def valid_group():
    return [
        event("anchor", "RUNTIME_OBSERVATION", "s1"),
        event("decision", "SECURITY_DECISION", None),
        event("result", "SECURITY_RESULT", None),
        event("status", "RUN_STATUS", None),
        event("execution", "EXECUTION_RESULT", "s1"),
    ]


def matches(events):
    return runtime_event_group_matches(events, "r1", "t1", "s1")


def test_anchored_group_preserves_original_missing_ids():
    events = valid_group()
    assert matches(events)
    assert [item.scenario_id for item in events] == ["s1", None, None, None, "s1"]


def test_explicit_scenario_events_remain_compatible():
    assert matches([event("a", "SECURITY_DECISION", "s1")])


def test_null_scenario_without_runtime_observation_is_rejected():
    assert not matches(valid_group()[1:])


@pytest.mark.parametrize("field,value", [
    ("run_id", "foreign"), ("trace_id", "foreign"),
    ("scenario_id", "foreign"), ("event_type", "MODEL_RESPONSE"),
    ("payload", {"run_id": "foreign"}),
    ("payload", {"trace_id": "foreign"}),
    ("payload", {"scenario_id": "foreign"}),
])
def test_conflicting_event_rejected(field, value):
    events = valid_group()
    setattr(events[1], field, value)
    assert not matches(events)


@pytest.mark.parametrize("field,value", [
    ("run_id", "foreign"), ("trace_id", "foreign"),
    ("scenario_id", "foreign"), ("payload", {}),
    ("payload", {"run_id": "r1", "trace_id": "t1", "scenario_id": "foreign"}),
])
def test_foreign_or_unsubstantiated_anchor_rejected(field, value):
    events = valid_group()
    setattr(events[0], field, value)
    assert not matches(events)


def test_duplicate_reference_rejected():
    events = valid_group()
    assert not matches(events + [events[0]])
