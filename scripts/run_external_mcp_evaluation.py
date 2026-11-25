"""Run external mapping or fixture validation; actual execution is unavailable."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT / "src", ROOT / "shared"):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from evaluation.external_mcp_cli import main

if __name__ == "__main__":
    raise SystemExit(main())
