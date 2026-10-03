"""Guard config loader.

Reads which guards are enabled/disabled and their priority/order from a
YAML file, so activation state is configuration, not hardcoded logic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_guard_config(path: str | Path) -> dict[str, dict[str, Any]]:
    """Load guard config.

    Expected YAML shape:
        guards:
          input_guard:
            enabled: true
            priority: 10
          tool_guard:
            enabled: true
            priority: 20
    Returns a dict keyed by guard name.
    """
    path = Path(path)
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return raw.get("guards", {})
