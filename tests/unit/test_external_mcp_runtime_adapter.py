
"""Test external benchmark mapping into Agent Runtime inputs."""

from copy import deepcopy

import pytest

from evaluation.external_mcp_adapter import build_bipia_pair
from evaluation.external_mcp_runtime_adapter import (
    build_agent_case_kwargs,
)
from evaluation.msb_mcp_adapter import build_msb_pair


def bipia_cases():
    return build_bipia_pair(
        source={
            "context": "Example document. Revenue increased by 5%.",
            "question": "How much did revenue increase?",
            "ideal": "5%",
        },
        attack="Synthetic injection test instruction.",
        provenance={"pair_id": "test-bipia-001"},
    )


@pytest.mark.parametrize("index", [0, 1])
def test_bipia_mapping(index):
    case = bipia_cases()[index]
    before = deepcopy(case)

    result = build_agent_case_kwargs(case)

    assert result["scenario_id"] == case["scenario_id"]
    assert result["user_input"] == case["legitimate_task"]
    assert result["documents"] == {
        "docs/benchmark.txt": case["document_content"],
    }
    assert result["tool_descriptions"] == {}
    assert case == before


@pytest.mark.parametrize("index", [0, 1])
def test_msb_mapping(index):
    case = build_msb_pair(
        "Synthetic template: {goal}",
        provenance={},
    )[index]

    before = deepcopy(case)
    result = build_agent_case_kwargs(case)

    assert result["scenario_id"] == case["scenario_id"]
    assert result["user_input"] == case["legitimate_task"]
    assert result["documents"] == {
        "docs/benchmark.txt": case["document_content"],
    }
    assert result["tool_descriptions"] == {
        "demo/read_file": case["tool_description"],
    }
    assert case == before


def test_invalid_attack_boundary_rejected():
    case = bipia_cases()[1]
    case["entry_surface"] = "tool_metadata"

    with pytest.raises(ValueError, match="boundary"):
        build_agent_case_kwargs(case)


def test_unsupported_attack_rejected():
    case = bipia_cases()[1]
    case["attack_id"] = "unsupported"

    with pytest.raises(ValueError, match="Unsupported"):
        build_agent_case_kwargs(case)


def test_non_external_case_rejected():
    case = bipia_cases()[0]
    case["source_type"] = "synthetic"

    with pytest.raises(ValueError, match="external"):
        build_agent_case_kwargs(case)


def test_execution_result_rejected():
    case = bipia_cases()[0]
    case["execution_scope"] = "actual_llm_mcp"

    with pytest.raises(ValueError, match="mapped case"):
        build_agent_case_kwargs(case)


def test_unexpected_tool_mapping_rejected():
    case = bipia_cases()[0]
    case["legitimate_tool_call"]["tool_name"] = "demo/send_email"

    with pytest.raises(ValueError, match="tool mapping"):
        build_agent_case_kwargs(case)
