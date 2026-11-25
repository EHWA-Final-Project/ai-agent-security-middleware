"""Validate synthetic scenario compatibility with Demo MCP."""

from pathlib import Path

import pytest

from evaluation.mcp_execution_adapter import (
    map_synthetic_scenario,
    map_tool_call,
)
from evaluation.mcp_scenarios import (
    ToolCallSpec,
    load_mcp_scenarios,
)

MANIFEST = (
    Path(__file__).resolve().parents[2] / "benchmarks" / "mcp_sprint1_scenarios.json"
)


def test_all_twelve_scenarios_map_to_demo():
    manifest = load_mcp_scenarios(MANIFEST)
    mapped = [map_synthetic_scenario(row) for row in manifest.scenarios]

    assert len(mapped) == 12

    for original, result in zip(manifest.scenarios, mapped, strict=True):
        assert result["scenario_id"] == original.scenario_id
        assert result["sample_id"] == original.sample_id
        assert result["classification"] == original.classification
        assert result["source_type"] == "synthetic"
        assert result["execution_scope"] == "mapping_only"

        assert result["lower_trust_payload"] == original.lower_trust_payload

        assert result["expected_bad_behavior"] == original.expected_bad_behavior

        for field in (
            "legitimate_tool_call",
            "intended_tool_call",
        ):
            call = result[field]
            assert call["server_name"] == "demo"
            assert call["tool_name"].startswith("demo/")

            if call["tool_name"] == "demo/send_email":
                assert isinstance(call["arguments"]["to"], str)


def test_mapping_does_not_modify_original_manifest():
    manifest = load_mcp_scenarios(MANIFEST)
    before = manifest.model_dump()

    for scenario in manifest.scenarios:
        map_synthetic_scenario(scenario)

    assert manifest.model_dump() == before


def test_email_recipient_mapping():
    call = ToolCallSpec(
        server_name="fixture-mcp",
        tool_name="send_email",
        arguments={
            "to": ["test@example.invalid"],
            "subject": "Test",
            "body": "Synthetic test",
        },
    )

    mapped = map_tool_call(call)

    assert mapped["tool_name"] == "demo/send_email"
    assert mapped["arguments"]["to"] == "test@example.invalid"
    assert call.arguments["to"] == ["test@example.invalid"]


@pytest.mark.parametrize(
    "recipients",
    [
        [],
        ["a@example.invalid", "b@example.invalid"],
        "a@example.invalid",
        [""],
    ],
)
def test_unsupported_recipient_formats_rejected(recipients):
    call = ToolCallSpec(
        server_name="fixture-mcp",
        tool_name="send_email",
        arguments={
            "to": recipients,
            "subject": "Test",
            "body": "Synthetic test",
        },
    )

    with pytest.raises(ValueError):
        map_tool_call(call)


def test_mapping_preserves_expected_outcomes_without_results():
    manifest = load_mcp_scenarios(MANIFEST)

    for scenario in manifest.scenarios:
        result = map_synthetic_scenario(scenario)

        assert result["semantic_oracle"] == scenario.semantic_oracle

        assert "attack_objective_achieved" not in result
        assert "legitimate_task_success" not in result
        assert "tool_executed" not in result
