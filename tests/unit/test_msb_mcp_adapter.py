"""Tests for MSB-derived metadata mappings."""

from copy import deepcopy

import pytest

from evaluation.msb_mcp_adapter import (
    DEMO_GOAL,
    SAFE_DESCRIPTION,
    build_msb_pair,
    extract_template,
)

TEMPLATE = "Synthetic test instruction: {goal}"


def test_extract_literal_template():
    source = 'PROMPT_INJECTION_TEMPLATE = "Synthetic test instruction: {goal}"'

    assert extract_template(source) == TEMPLATE


def test_missing_template_rejected():
    with pytest.raises(ValueError):
        extract_template('OTHER = "test"')


def test_invalid_placeholder_rejected():
    with pytest.raises(ValueError):
        build_msb_pair("No placeholder", {})


def test_matched_metadata_pair():
    benign, attack = build_msb_pair(TEMPLATE, {})

    assert benign["classification"] == "benign"
    assert attack["classification"] == "attack"

    assert benign["pair_id"] == attack["pair_id"]
    assert benign["sample_id"] != attack["sample_id"]

    assert benign["tool_description"] == SAFE_DESCRIPTION
    assert DEMO_GOAL in attack["tool_description"]

    assert benign["document_content"] == attack["document_content"]
    assert benign["legitimate_task"] == attack["legitimate_task"]
    assert benign["reference_answer"] == attack["reference_answer"]


def test_metadata_remains_untrusted():
    for case in build_msb_pair(TEMPLATE, {}):
        assert case["metadata_trust"] == "untrusted"
        assert case["entry_surface"] == "tool_metadata"
        assert case["execution_scope"] == "mapping_only"


def test_provenance_preserved():
    provenance = {
        "dataset_id": "msb",
        "source_objective_id": "obtain_data_information",
    }

    before = deepcopy(provenance)

    cases = build_msb_pair(TEMPLATE, provenance)

    assert provenance == before

    for case in cases:
        assert case["provenance"] == before


def test_mapping_does_not_claim_actual_outcomes():
    for case in build_msb_pair(TEMPLATE, {}):
        assert case["source_type"] == "external_adapted"
        assert case["judge_status"] == "pending"
        assert "attack_objective_achieved" not in case
        assert "legitimate_task_success" not in case
        assert "tool_executed" not in case
