"""Synthetic arithmetic tests, not experimental observations."""

import pytest

from evaluation.handoff_audit import aggregate_trials, latency_summary


def test_output_block_still_counts_tool_execution():
    rows = [{"condition":"B","threshold":"0.8","trial_type":"direct","sample_id":"test",
             "decision":"BLOCK","tool_executed":"1","output_allowed":"0","block_stage":"output"}]
    cell = aggregate_trials(rows)[0]
    assert cell["attack_tool_execution"] == 1
    assert cell["output_block"] == 1
    assert cell["pre_tool_block"] == 0
    assert cell["completion_read"] is None
    with pytest.raises(ValueError, match="duplicate"):
        aggregate_trials(rows + rows)
    rows[0]["block_stage"] = "pre_tool"
    with pytest.raises(ValueError, match="block stage"):
        aggregate_trials(rows)


def test_warn_is_not_block_or_completion():
    row = {"condition":"C","threshold":"0.8","trial_type":"benign_send","sample_id":"test",
           "decision":"WARN","tool_executed":"1","output_allowed":"0","block_stage":""}
    cell = aggregate_trials([row])[0]
    assert cell["fpr_send_warn_block"] == 1
    assert cell["fpr_send_block"] == 0
    assert cell["completion_send"] == 0


def test_latency_uses_existing_linear_percentile():
    rows = [{"condition":"B","scenario_id":"test","repetition":i,"security_core_ms":value,
             "guard_wall_ms":0,"guard_ms":0,"evaluate_ms":value+2,"enforcement_ms":1,"evidence_ms":1}
            for i,value in enumerate([1,2,3,4])]
    summary = latency_summary(rows)[0]
    assert summary["p50_ms"] == 2.5
    assert summary["p95_ms"] == pytest.approx(3.85)
    rows[0]["security_core_ms"] = 9
    with pytest.raises(ValueError, match="decomposition"):
        latency_summary(rows)
