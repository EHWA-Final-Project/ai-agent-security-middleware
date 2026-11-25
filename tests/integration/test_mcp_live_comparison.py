"""Run the real MCP SDK B/C comparison as a regression test."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "examples" / "run_mcp_linked_comparison.py"


def test_live_mcp_linked_comparison(tmp_path):
    output_dir = tmp_path / "mcp_live_comparison"

    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(ROOT), str(ROOT / "src"), str(ROOT / "shared"), str(ROOT / "examples")]
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--output-dir",
            str(output_dir),
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )

    assert result.returncode == 0, (
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )

    rows = json.loads(
        (output_dir / "comparison.json").read_text(encoding="utf-8")
    )
    by_condition = {row["condition"]: row for row in rows}

    assert set(by_condition) == {"B", "C"}

    b = by_condition["B"]
    c = by_condition["C"]

    assert b["sdk_calls"] == 1
    assert b["executed"] is True
    assert b["output_allowed"] is False

    assert c["sdk_calls"] == 0
    assert c["executed"] is False
    assert c["guard_decision"] == "BLOCK"
    assert c["output_allowed"] is False

    assert all(
        row["runtime_status"] == "COMPLETED" and not row["errors"]
        for row in rows
    )
