"""Synthetic MCP specification to Demo MCP execution mapping."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from .mcp_scenarios import ScenarioSpec, ToolCallSpec

ADAPTER_VERSION = "mcp-demo-mapping-v1"

SUPPORTED_SURFACES = {
    "tool_metadata": "metadata_exposure_required",
    "tool_response": "response_exposure_required",
    "resource_content": "resource_support_required",
    "tool_request": "candidate_execution_supported",
}


def map_tool_call(call: ToolCallSpec) -> dict[str, Any]:
    """Map a fixture tool specification without mutating its source."""
    if call.server_name != "fixture-mcp":
        raise ValueError("Unsupported fixture server")

    arguments = deepcopy(call.arguments)

    if call.tool_name == "read_file":
        if set(arguments) != {"path"}:
            raise ValueError("Invalid read_file arguments")

        if not isinstance(arguments["path"], str):
            raise ValueError("read_file path must be a string")

    elif call.tool_name == "send_email":
        if set(arguments) != {"to", "subject", "body"}:
            raise ValueError("Invalid send_email arguments")

        recipients = arguments["to"]

        if (
            not isinstance(recipients, list)
            or len(recipients) != 1
            or not isinstance(recipients[0], str)
            or not recipients[0].strip()
        ):
            raise ValueError("Expected exactly one fixture recipient")

        arguments["to"] = recipients[0]

        for key in ("subject", "body"):
            if not isinstance(arguments[key], str):
                raise TypeError(f"{key} must be a string")

    else:
        raise ValueError("Unsupported fixture tool")

    return {
        "server_name": "demo",
        "tool_name": f"demo/{call.tool_name}",
        "arguments": arguments,
    }


def map_synthetic_scenario(
    scenario: ScenarioSpec,
) -> dict[str, Any]:
    """Prepare a mapping, not an observed execution result."""
    return {
        "adapter_version": ADAPTER_VERSION,
        "source_type": "synthetic",
        "execution_scope": "mapping_only",
        "scenario_id": scenario.scenario_id,
        "sample_id": scenario.sample_id,
        "pair_id": scenario.pair_id,
        "attack_id": scenario.attack_id,
        "classification": scenario.classification,
        "entry_surface": scenario.entry_surface,
        "surface_requirement": SUPPORTED_SURFACES[scenario.entry_surface],
        "legitimate_task": scenario.legitimate_task,
        "lower_trust_payload": scenario.lower_trust_payload,
        "legitimate_tool_call": map_tool_call(scenario.legitimate_tool_call),
        "intended_tool_call": map_tool_call(scenario.intended_tool_call),
        "expected_good_behavior": scenario.expected_good_behavior,
        "expected_bad_behavior": scenario.expected_bad_behavior,
        "semantic_oracle": scenario.semantic_oracle,
        "policy_fixture": scenario.policy_fixture,
        "conditions_to_observe": list(scenario.conditions_to_observe),
        "transformation": {
            "server": "fixture-mcp -> demo",
            "tool_name": "server/tool namespace",
            "email_to": "single-element list -> string",
        },
    }
