"""Historical replay must reject broken joins and retain unknown observations."""

import sys
from copy import deepcopy
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "demo"))
from actual_results import boundary, display, load_results, validate_results


@pytest.fixture
def actual_data():
    return load_results()


def test_historical_cohort_has_complete_matrix_and_preserves_unknown(actual_data):
    assert len(actual_data["trial_observations"]) == 48
    assert len(actual_data["candidate_observations"]) == 52
    assert all(t["final_user_delivery"] is None for t in actual_data["trial_observations"])
    assert display(None) != display(0)
    assert all(m["rate"] is None for m in actual_data["report_summary_ko"]["공식지표"].values())


@pytest.mark.parametrize("table", ["candidate_observations", "individual_guard_results", "model_tool_selections"])
def test_reject_cross_trial_identity(actual_data, table):
    actual_data[table][0]["run_id"] = "unrelated-run"
    with pytest.raises(ValueError, match="identity mismatch"):
        validate_results(actual_data)


def test_reject_duplicate_trial(actual_data):
    actual_data["trial_observations"][1] = deepcopy(actual_data["trial_observations"][0])
    with pytest.raises(ValueError, match="identity/count"):
        validate_results(actual_data)


def test_reject_false_pre_execution_block(actual_data):
    row = next(r for r in actual_data["candidate_observations"] if r["executed"] is True)
    row["pre_execution_block"] = True
    with pytest.raises(ValueError, match="contradicts"):
        validate_results(actual_data)


def test_reject_incorrect_rate(actual_data):
    actual_data["operational_metrics"][0]["rate"] = 1
    with pytest.raises(ValueError, match="rate differs"):
        validate_results(actual_data)


def test_executed_withheld_is_separate_from_guard_block(actual_data):
    rows = [r for r in actual_data["candidate_observations"] if r["output_withheld"] is True]
    assert rows
    assert all(boundary(r) == "EXECUTED + 출력 미전달" for r in rows)
    assert any(r["output_guard_block"] is False for r in rows)
    assert boundary({}) == "알 수 없음"
