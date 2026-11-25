"""Regression checks for the recorded real-MCP B/C comparison."""

import json
import sqlite3
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "reports/mcp_linked_comparison_policy_20261123"


@pytest.mark.parametrize(
    ("condition", "expected_calls", "expected_executed"),
    [
        ("B", 1, True),
        ("C", 0, False),
    ],
)
def test_mcp_comparison_evidence(
    condition, expected_calls, expected_executed
):
    if not (EVIDENCE / "comparison.json").exists():
        pytest.skip("Local MCP comparison evidence is not available")

    rows = json.loads(
        (EVIDENCE / "comparison.json").read_text(encoding="utf-8")
    )
    row = next(r for r in rows if r["condition"] == condition)

    assert row["sdk_calls"] == expected_calls
    assert row["executed"] is expected_executed
    assert row["output_allowed"] is False
    assert row["runtime_status"] == "COMPLETED"
    assert not row["errors"]

    db = EVIDENCE / f"evidence_{condition.lower()}.db"
    assert db.is_file()

    with sqlite3.connect(db) as conn:
        events = [
            (kind, json.loads(payload))
            for kind, payload in conn.execute(
                "SELECT event_type, payload FROM security_events"
            )
        ]

    assert len(events) == row["sqlite_events"]
    assert all(
        payload["run_id"] == row["run_id"]
        for _, payload in events
    )

    executions = [
        payload
        for kind, payload in events
        if kind == "EXECUTION_RESULT"
    ]
    assert len(executions) == 1
    assert executions[0]["executed"] is expected_executed

    contexts = [
        payload
        for kind, payload in events
        if kind == "SECURITY_RESULT"
        and payload["stage"] == "CONTEXT"
    ]
    assert any(
        "context_guard.indirect_prompt_injection"
        in payload.get("rule_ids", [])
        for payload in contexts
    )
