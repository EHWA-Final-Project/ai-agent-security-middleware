uv sync --frozen
uv pip install "fastapi>=0.118,<1" "uvicorn>=0.37,<1" "httpx>=0.28,<1"
PYTHONPATH=src:shared uv run uvicorn platform_api.app:app --host 127.0.0.1 --port 8000
