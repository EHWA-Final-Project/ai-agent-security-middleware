"""AgentLLM for any OpenAI-compatible chat-completions endpoint (stdlib only).

One class covers hosted providers that expose ``/chat/completions`` and local servers
such as Ollama, so changing provider means changing environment variables only:

    LLM_BASE_URL   e.g. https://api.example.com/v1  or  http://localhost:11434/v1
    LLM_API_KEY    secret; read from the environment, never logged or written to results
    LLM_MAX_TOKENS optional output cap (default 512). Thinking models (e.g. qwen3) spend
                   tokens on reasoning first, so raise it (e.g. 2048) if no tool call comes back.
    LLM_TIMEOUT_SEC optional per-request timeout in seconds (default 60). A local model can
                   need several minutes per call on a laptop.
    LLM_MAX_TOKENS_PARAM  optional: "max_tokens" (default) or "max_completion_tokens"
                   (some newer OpenAI models only accept the second name)
    LLM_MODEL      model name sent in the request

No SDK and no new dependency (uv.lock unchanged). The model name returned by the
server is recorded in ``LLMReply.model`` so every result row carries it.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from agent_document_assistant import LLMReply, ToolIntent

_PARAM_TYPES = {"string": {"type": "string"}, "list[string]": {"type": "array", "items": {"type": "string"}}}


class AgentLLMError(RuntimeError):
    """Provider call failed. The message never contains the API key."""


def _to_function_tools(specs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    tools = []
    for spec in specs:
        props = {k: _PARAM_TYPES.get(v, {"type": "string"}) for k, v in spec["parameters"].items()}
        tools.append({"type": "function", "function": {
            "name": spec["name"], "description": spec["description"],
            "parameters": {"type": "object", "properties": props, "required": list(props)}}})
    return tools


@dataclass
class OpenAICompatibleLLM:
    base_url: str
    model: str
    api_key: str = ""
    timeout_sec: float = 60.0
    temperature: float = 0.0
    max_tokens: int = 512
    max_tokens_param: str = "max_tokens"

    diagnostics: bool = False

    @classmethod
    def from_env(cls) -> OpenAICompatibleLLM:
        missing = [k for k in ("LLM_BASE_URL", "LLM_MODEL") if not os.environ.get(k)]
        if missing:
            raise AgentLLMError(f"missing environment variables: {', '.join(missing)}")
        param = os.environ.get("LLM_MAX_TOKENS_PARAM", "max_tokens")
        if param not in ("max_tokens", "max_completion_tokens"):
            raise AgentLLMError("LLM_MAX_TOKENS_PARAM must be max_tokens or max_completion_tokens")
        try:
            max_tokens = int(os.environ.get("LLM_MAX_TOKENS", "512"))
        except ValueError:
            raise AgentLLMError("LLM_MAX_TOKENS must be an integer") from None
        try:
            timeout = float(os.environ.get("LLM_TIMEOUT_SEC", "60"))
        except ValueError:
            raise AgentLLMError("LLM_TIMEOUT_SEC must be a number") from None
        return cls(os.environ["LLM_BASE_URL"], os.environ["LLM_MODEL"], os.environ.get("LLM_API_KEY", ""),
                   timeout_sec=timeout, max_tokens=max_tokens, max_tokens_param=param,
                   diagnostics=os.environ.get("LLM_DIAGNOSTICS") == "1")

    def decide(self, system, user_input, context_items, tools) -> LLMReply:
        document = "\n\n".join(f"[document {i + 1}]\n{c}" for i, c in enumerate(context_items))
        user = f"Task: {user_input}" + (f"\n\nReference documents:\n{document}" if document else "")
        return self.decide_messages([{"role": "system", "content": system}, {"role": "user", "content": user}], tools)

    def decide_messages(self, messages, tools) -> LLMReply:
        body = {"model": self.model, "temperature": self.temperature, self.max_tokens_param: self.max_tokens,
                "messages": messages}
        if tools:  # no tools -> plain chat request (used by the Jailbreak pilot)
            body["tools"] = _to_function_tools(tools)
            body["tool_choice"] = "auto"
        if self.diagnostics:
            # Describe the outbound payload without printing free-form strings or headers.
            summary = [{"role": msg["role"], "content_chars": len(msg.get("content") or ""),
                        "tool_calls": len(msg.get("tool_calls", []))} for msg in messages]
            print(json.dumps({"messages": summary, "available_tools": [t["name"] for t in tools]}),
                  file=sys.stderr)
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = urllib.request.Request(self.base_url.rstrip("/") + "/chat/completions",
                                         data=json.dumps(body).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_sec) as response:
                data = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            raise AgentLLMError(f"provider returned HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise AgentLLMError(f"provider call failed: {type(exc).__name__}") from None

        message = (data.get("choices") or [{}])[0].get("message") or {}
        calls = message.get("tool_calls") or []
        intent = None
        if calls:
            function = calls[0].get("function") or {}
            try:
                arguments = json.loads(function.get("arguments") or "{}")
            except json.JSONDecodeError:
                arguments = {}
            if function.get("name") and isinstance(arguments, dict):
                intent = ToolIntent(function["name"], arguments)
        return LLMReply(text=message.get("content") or "", tool_call=intent, model=data.get("model") or self.model,
                        tool_call_id=(calls[0].get("id") or "") if calls else "")
