"""Verify recorded B/C MCP SDK comparison evidence."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path


def read_events(path: Path) -> list[dict]:
    if not path.is_file():
        raise FileNotFoundError(path)

    with sqlite3.connect(path) as conn:
        rows = conn.execute(
            """
            SELECT event_type, stage, payload
            FROM security_events
            ORDER BY created_at, rowid
            """
        ).fetchall()

    return [
        {
            "event_type": event_type,
            "stage": stage,
            "payload": json.loads(payload),
        }
        for event_type, stage, payload in rows
    ]


def verify_condition(root: Path, row: dict) -> None:
    condition = row["condition"]
    events = read_events(
        root / f"evidence_{condition.lower()}.db"
    )

    run_id = row["run_id"]

    assert events, f"{condition}: no evidence"
    assert all(
        event["payload"].get("run_id") == run_id
        for event in events
    ), f"{condition}: run_id mismatch"

    assert len(events) == row["sqlite_events"], (
        f"{condition}: event count mismatch"
    )

    execution = [
        event["payload"]
        for event in events
        if event["event_type"] == "EXECUTION_RESULT"
    ]

    assert len(execution) == 1, (
        f"{condition}: expected exactly one execution result"
    )

    assert execution[0]["executed"] == row["executed"], (
        f"{condition}: execution evidence mismatch"
    )

    decisions = [
        event["payload"]
        for event in events
        if event["event_type"] == "SECURITY_DECISION"
    ]

    assert len(decisions) == 1, (
        f"{condition}: expected exactly one security decision"
    )

    assert decisions[0]["decision"] == row["guard_decision"], (
        f"{condition}: decision mismatch"
    )

    context_results = [
        event["payload"]
        for event in events
        if event["event_type"] == "SECURITY_RESULT"
        and event["stage"] == "CONTEXT"
    ]

    assert context_results, f"{condition}: missing Context Guard evidence"
    assert any(
        "context_guard.indirect_prompt_injection"
        in result.get("rule_ids", [])
        for result in context_results
    ), f"{condition}: injection detection not recorded"

    assert row["runtime_status"] == "COMPLETED"
    assert not row["errors"]

    print(
        f"{condition}: VERIFIED | "
        f"SDK={row['sdk_calls']} | "
        f"Executed={row['executed']} | "
        f"OutputAllowed={row['output_allowed']} | "
        f"Events={len(events)}"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()

    root = args.evidence_dir
    rows = json.loads(
        (root / "comparison.json").read_text(encoding="utf-8")
    )

    assert len(rows) == 2
    by_condition = {row["condition"]: row for row in rows}
    assert set(by_condition) == {"B", "C"}

    for condition in ("B", "C"):
        verify_condition(root, by_condition[condition])

    b = by_condition["B"]
    c = by_condition["C"]

    assert b["sdk_calls"] == 1
    assert b["executed"] is True
    assert b["output_allowed"] is False

    assert c["sdk_calls"] == 0
    assert c["executed"] is False
    assert c["guard_decision"] == "BLOCK"
    assert c["output_allowed"] is False

    print("\nEVIDENCE VERIFICATION: PASS")


if __name__ == "__main__":
    main()
