"""Plot tests use synthetic counts, not holdout results."""

import pytest

from evaluation.handoff_audit import aggregate_trials
from evaluation.handoff_plots import benign_rows, caption, render_figures


def cells():
    rows = []
    for mode in ("B", "C"):
        for threshold in ("0.73", "0.94"):
            for kind in ("direct", "indirect", "benign_read", "benign_send"):
                rows.append({"condition":mode,"threshold":threshold,"trial_type":kind,"sample_id":kind,
                             "decision":"ALLOW","tool_executed":"1","output_allowed":"1","block_stage":""})
    return aggregate_trials(rows)


def test_threshold_grouping_preserves_changed_completion():
    data = cells()
    assert len(benign_rows(data)) == 4
    data[0]["completion_send_numerator"] = 0
    assert len(benign_rows(data)) == 5
    assert "1/1 (100.0%)" in benign_rows(data)[0]


def test_explicit_split_and_holdout_render(tmp_path):
    assert caption("tune") == "tuning split, provisional"
    with pytest.raises(ValueError):
        caption("unknown")
    render_figures(tmp_path,cells(),[],{},split="holdout",sources=["synthetic"],toolpolicy="absent")
    assert {p.stem for p in tmp_path.glob('*.png')} == {"attack_tool_execution","direct_indirect","benign_warn_block"}
    assert all(p.stat().st_size > 1000 for p in tmp_path.iterdir())
