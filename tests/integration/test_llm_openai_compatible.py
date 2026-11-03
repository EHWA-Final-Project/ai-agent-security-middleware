"""OpenAI-compatible client against a local fake server (no network, no key)."""

import importlib.util
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

_EX = Path(__file__).parents[2] / "examples"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, _EX / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


agent = _load("agent_document_assistant")
client = _load("llm_openai_compatible")


class _Handler(BaseHTTPRequestHandler):
    seen: ClassVar[dict] = {}
    reply: ClassVar[dict] = {}
    status = 200

    def do_POST(self):
        _Handler.seen = {"path": self.path, "auth": self.headers.get("Authorization"),
                         "body": json.loads(self.rfile.read(int(self.headers["Content-Length"])))}
        self.send_response(_Handler.status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(_Handler.reply).encode())

    def log_message(self, *args):
        pass


@pytest.fixture()
def server():
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    _Handler.status = 200
    yield f"http://127.0.0.1:{httpd.server_port}/v1"
    httpd.shutdown()


def test_tool_call_is_parsed_and_request_is_well_formed(server):
    _Handler.reply = {"model": "fake-model-1", "choices": [{"message": {"content": None, "tool_calls": [
        {"function": {"name": "send_email", "arguments": json.dumps({"to": ["a@b.invalid"], "subject": "s", "body": "b"})}}]}}]}
    llm = client.OpenAICompatibleLLM(server, "fake", api_key="k-123")
    reply = llm.decide(agent.SYSTEM_PROMPT, "Summarize.", ["doc text"], agent.TOOL_SPECS)

    assert reply.tool_call == agent.ToolIntent("send_email", {"to": ["a@b.invalid"], "subject": "s", "body": "b"})
    assert reply.model == "fake-model-1"
    seen = _Handler.seen
    assert seen["path"] == "/v1/chat/completions" and seen["auth"] == "Bearer k-123"
    assert seen["body"]["temperature"] == 0.0 and seen["body"]["tool_choice"] == "auto"
    names = [t["function"]["name"] for t in seen["body"]["tools"]]
    assert names == ["read_file", "send_email"]
    assert "[document 1]\ndoc text" in seen["body"]["messages"][1]["content"]


def test_plain_text_reply_has_no_tool_call(server):
    _Handler.reply = {"choices": [{"message": {"content": "hello"}}]}
    reply = client.OpenAICompatibleLLM(server, "fake").decide("s", "u", [], agent.TOOL_SPECS)
    assert reply.text == "hello" and reply.tool_call is None and reply.model == "fake"


def test_malformed_arguments_do_not_become_a_tool_call(server):
    _Handler.reply = {"choices": [{"message": {"tool_calls": [{"function": {"name": "read_file", "arguments": "{oops"}}]}}]}
    reply = client.OpenAICompatibleLLM(server, "fake").decide("s", "u", [], agent.TOOL_SPECS)
    assert reply.tool_call == agent.ToolIntent("read_file", {})


def test_http_error_message_never_contains_the_key(server):
    _Handler.status, _Handler.reply = 401, {"error": "bad key k-secret-999"}
    with pytest.raises(client.AgentLLMError) as info:
        client.OpenAICompatibleLLM(server, "fake", api_key="k-secret-999").decide("s", "u", [], agent.TOOL_SPECS)
    assert "k-secret-999" not in str(info.value) and "401" in str(info.value)


def test_from_env_requires_url_and_model(monkeypatch):
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    with pytest.raises(client.AgentLLMError):
        client.OpenAICompatibleLLM.from_env()
    monkeypatch.setenv("LLM_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("LLM_MODEL", "m")
    assert client.OpenAICompatibleLLM.from_env().api_key == ""


def test_output_cap_parameter_name_is_configurable(server):
    _Handler.reply = {"choices": [{"message": {"content": "ok"}}]}
    client.OpenAICompatibleLLM(server, "fake", max_tokens_param="max_completion_tokens").decide("s", "u", [], agent.TOOL_SPECS)
    body = _Handler.seen["body"]
    assert body["max_completion_tokens"] == 512 and "max_tokens" not in body
    client.OpenAICompatibleLLM(server, "fake").decide("s", "u", [], agent.TOOL_SPECS)
    assert _Handler.seen["body"]["max_tokens"] == 512


def test_from_env_rejects_unknown_cap_parameter_name(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "http://x/v1")
    monkeypatch.setenv("LLM_MODEL", "m")
    monkeypatch.setenv("LLM_MAX_TOKENS_PARAM", "limit")
    with pytest.raises(client.AgentLLMError):
        client.OpenAICompatibleLLM.from_env()


def test_from_env_reads_output_cap(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "http://x/v1")
    monkeypatch.setenv("LLM_MODEL", "m")
    monkeypatch.delenv("LLM_MAX_TOKENS_PARAM", raising=False)
    monkeypatch.setenv("LLM_MAX_TOKENS", "2048")
    assert client.OpenAICompatibleLLM.from_env().max_tokens == 2048
    monkeypatch.setenv("LLM_MAX_TOKENS", "lots")
    with pytest.raises(client.AgentLLMError):
        client.OpenAICompatibleLLM.from_env()


def test_from_env_reads_timeout(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "http://x/v1")
    monkeypatch.setenv("LLM_MODEL", "m")
    monkeypatch.delenv("LLM_MAX_TOKENS", raising=False)
    monkeypatch.delenv("LLM_MAX_TOKENS_PARAM", raising=False)
    monkeypatch.setenv("LLM_TIMEOUT_SEC", "600")
    assert client.OpenAICompatibleLLM.from_env().timeout_sec == 600.0
    monkeypatch.setenv("LLM_TIMEOUT_SEC", "soon")
    with pytest.raises(client.AgentLLMError):
        client.OpenAICompatibleLLM.from_env()
