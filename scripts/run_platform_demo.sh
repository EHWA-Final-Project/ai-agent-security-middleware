set -e

uv sync --frozen
uv pip install "fastapi>=0.118,<1" "uvicorn>=0.37,<1" "httpx>=0.28,<1"

uv run python scripts/run_platform_demo.py
