
"""Map verified external benchmark cases to Agent Runtime inputs."""

from __future__ import annotations

from typing import Any


def build_agent_case_kwargs(case: dict[str, Any]) -> dict[str, Any]:
    """Preserve the mapped task and its designated untrusted boundary."""

    if case.get("source_type") != "external_adapted":
        raise ValueError("Expected an external benchmark case")

    if case.get("execution_scope") != "mapping_only":
        raise ValueError("Expected a mapped case, not execution results")

    if case.get("policy_fixture") != "read_only":
        raise ValueError("Unsupported policy fixture")

    if case.get("legitimate_tool_call") != {
        "server_name": "demo",
        "tool_name": "demo/read_file",
        "arguments": {"path": "docs/benchmark.txt"},
    }:
        raise ValueError("Unexpected legitimate tool mapping")

    scenario_id = case["scenario_id"]
    user_input = case["legitimate_task"]
    document = case["document_content"]

    for name, value in (
        ("scenario_id", scenario_id),
        ("legitimate_task", user_input),
        ("document_content", document),
    ):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Invalid {name}")

    tool_descriptions: dict[str, str] = {}

    if case.get("attack_id") == "PI-T01":
        if case.get("entry_surface") != "tool_response":
            raise ValueError("PI-T01 requires the tool response boundary")

        if "tool_description" in case:
            raise ValueError("Unexpected tool metadata in PI-T01 case")

    elif case.get("attack_id") == "MCP-D01":
        if case.get("entry_surface") != "tool_metadata":
            raise ValueError("MCP-D01 requires the tool metadata boundary")

        description = case.get("tool_description")

        if not isinstance(description, str) or not description.strip():
            raise ValueError("Missing tool description")

        tool_descriptions["demo/read_file"] = description

    else:
        raise ValueError("Unsupported external attack type")

    return {
        "scenario_id": scenario_id,
        "user_input": user_input,
        "documents": {
            "docs/benchmark.txt": document,
        },
        "tool_descriptions": tool_descriptions,
    }
