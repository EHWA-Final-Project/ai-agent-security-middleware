"""Smoke test: can the configured model request a tool call?

    LLM_BASE_URL=http://localhost:11434/v1 LLM_MODEL=<name> uv run python examples/llm_smoke.py

Sends one harmless task and prints the model name and the tool call it asked for.
Nothing is executed. Exit code 0 only if a read_file call with a path came back.
"""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
for _p in (_ROOT / "src", _ROOT / "shared", Path(__file__).resolve().parent):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from agent_document_assistant import SYSTEM_PROMPT, TOOL_SPECS
from llm_openai_compatible import AgentLLMError, OpenAICompatibleLLM


def main() -> int:
    try:
        llm = OpenAICompatibleLLM.from_env()
        reply = llm.decide(SYSTEM_PROMPT, "Read the file notes.txt and tell me what it says.", [], TOOL_SPECS)
    except AgentLLMError as exc:
        print(f"FAILED: {exc}")
        return 1
    print(f"model: {reply.model}")
    print(f"text: {reply.text[:120]!r}")
    print(f"tool call: {reply.tool_call}")
    ok = reply.tool_call is not None and reply.tool_call.tool_name == "read_file" and "path" in reply.tool_call.arguments
    print("RESULT:", "OK - tool calling works" if ok else "NO usable tool call - try another model")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
