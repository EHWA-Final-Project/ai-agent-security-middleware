"""Synthetic contract checks; these are not model or MCP server results."""

import json
from dataclasses import asdict
from pathlib import Path

import pytest
from pydantic import ValidationError

from evaluation.mcp_scenarios import (
    SURFACES,
    BoundaryObservation,
    ScenarioManifest,
    load_mcp_scenarios,
)

MANIFEST = Path(__file__).resolve().parents[2] / "benchmarks" / "mcp_sprint1_scenarios.json"


@pytest.fixture
def raw():
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_manifest_covers_six_matched_pairs_without_observed_results():
    manifest = load_mcp_scenarios(MANIFEST)
    assert len(manifest.scenarios) == 12
    assert {row.attack_id for row in manifest.scenarios} == set(SURFACES)
    for row in manifest.scenarios:
        assert row.legitimate_tool_call.tool_name == "read_file"
        assert row.intended_tool_call.server_name == "fixture-mcp"
        assert not {"attack_success", "task_success", "expected_result", "scenario_type"} & row.model_dump().keys()


@pytest.mark.parametrize("field", ["scenario_id", "sample_id"])
def test_duplicate_ids_rejected(raw, field):
    raw["scenarios"][2][field] = raw["scenarios"][0][field]
    with pytest.raises(ValidationError, match="duplicate"):
        ScenarioManifest.model_validate(raw)


@pytest.mark.parametrize("field", [
    "sample_id", "entry_surface", "legitimate_task", "lower_trust_payload", "intended_tool_call",
    "expected_good_behavior", "expected_bad_behavior", "conditions_to_observe", "semantic_oracle",
])
def test_required_fields_rejected_when_missing(raw, field):
    del raw["scenarios"][0][field]
    with pytest.raises(ValidationError):
        ScenarioManifest.model_validate(raw)


@pytest.mark.parametrize(("field", "value"), [
    ("classification", "ALLOW"), ("entry_surface", "tool_response"),
    ("legitimate_task", "  "), ("conditions_to_observe", []),
    ("conditions_to_observe", [""]), ("expected_bad_behavior", None),
    ("lower_trust_payload", 123), ("attack_success", True),
])
def test_invalid_or_result_fields_rejected(raw, field, value):
    raw["scenarios"][0][field] = value
    with pytest.raises(ValidationError):
        ScenarioManifest.model_validate(raw)


def test_benign_cannot_have_an_attack_objective(raw):
    raw["scenarios"][1]["expected_bad_behavior"] = "Do something bad"
    with pytest.raises(ValidationError):
        ScenarioManifest.model_validate(raw)


def test_missing_counterpart_rejected(raw):
    raw["scenarios"].pop(1)
    with pytest.raises(ValidationError, match="pair requires"):
        ScenarioManifest.model_validate(raw)


def test_missing_family_rejected(raw):
    raw["scenarios"] = raw["scenarios"][2:]
    with pytest.raises(ValidationError, match="six attack families"):
        ScenarioManifest.model_validate(raw)


@pytest.mark.parametrize(("field", "value"), [
    ("legitimate_task", "A different task"), ("policy_fixture", "bounded_tools"),
    ("legitimate_tool_call", {"server_name": "fixture-mcp", "tool_name": "read_file",
                              "arguments": {"path": "docs/other.txt"}}),
])
def test_pair_drift_rejected(raw, field, value):
    raw["scenarios"][1][field] = value
    with pytest.raises(ValidationError, match="paired"):
        ScenarioManifest.model_validate(raw)


@pytest.mark.parametrize(("facts", "expected"), [
    ({}, "unknown"),
    ({"call_count": 0, "tool_executed": False}, "unknown"),
    ({"output_allowed": False}, "unknown"),
    ({"pre_tool_block": True}, "unknown"),
    ({"pre_tool_block": True, "call_count": 0, "tool_executed": False}, "pre_tool_block"),
    ({"call_count": 1, "tool_executed": False}, "unknown"),
    ({"call_count": 1, "tool_executed": True, "output_allowed": False}, "tool_executed"),
    ({"call_count": 1, "tool_executed": True, "output_allowed": False,
      "post_tool_output_block": True}, "post_tool_output_block"),
])
def test_boundary_classification_requires_explicit_evidence(facts, expected):
    observation = BoundaryObservation(**facts)
    assert observation.boundary_classification == expected
    assert not {"attack_success", "task_success", "guard_defense_success"} & asdict(observation).keys()


@pytest.mark.parametrize("facts", [
    {"pre_tool_block": True, "call_count": 1},
    {"pre_tool_block": True, "tool_executed": True},
    {"pre_tool_block": True, "post_tool_output_block": True},
    {"post_tool_output_block": True, "output_allowed": True},
    {"post_tool_output_block": True, "tool_executed": False},
    {"tool_executed": True, "call_count": 0},
    {"call_count": -1}, {"call_count": True}, {"call_count": 1.0}, {"tool_executed": 1},
])
def test_contradictory_or_coerced_boundary_facts_rejected(facts):
    with pytest.raises(ValueError):
        BoundaryObservation(**facts)


def test_missing_facts_stay_null():
    assert all(value is None for value in asdict(BoundaryObservation()).values())


def test_pi_t01_followup_block_does_not_erase_initial_call():
    initial = BoundaryObservation(call_count=1, tool_executed=True, output_allowed=True)
    followup = BoundaryObservation(pre_tool_block=True, call_count=0, tool_executed=False)
    assert initial.call_count + followup.call_count == 1
    assert followup.boundary_classification == "pre_tool_block"


def test_tl_x01_output_block_does_not_erase_simulated_sink_receipt():
    sink = [{"to": ["attacker@evil.invalid"], "body": "FAKE_MCP_SECRET_001"}]
    observation = BoundaryObservation(
        call_count=1, tool_executed=True, output_allowed=False, post_tool_output_block=True,
    )
    assert observation.boundary_classification == "post_tool_output_block"
    assert sink[0]["body"] == "FAKE_MCP_SECRET_001"
