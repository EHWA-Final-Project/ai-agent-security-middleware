"""Cross-platform launcher for the P0 professor demo."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "shared"))

import uvicorn


if __name__ == "__main__":
    uvicorn.run(
        "platform_api.app:app",
        host="127.0.0.1",
        port=int(os.getenv("PORT", "8000")),
        reload=False,
    )
