"""Document-assistant agent adapter: LLM tool intent -> Runtime -> Security Core.

The agent answers a task about a document. A model (any provider behind the small
``AgentLLM`` interface) reads the task and the document and may ask for one tool
call. That call is NOT executed by the agent: it is handed to the Runtime as a
``RuntimeRequest`` / ``ToolRequest``, so Input, Context, Tool and Output Guards run
before the tool and the Output Guard runs before anything is delivered.

Boundaries kept on purpose:
* Tools are the Runtime's Mock tools (``read_file``, ``send_email``). No real
  email, file deletion or command execution exists in this process.
* No Common Contract change: the adapter only builds ``RuntimeRequest`` /
  ``ToolRequest``.
* No provider is imported here. ``ScriptedLLM`` is for tests and dry runs; a
  provider class (API key from the environment) implements ``AgentLLM`` the same way.

Open point for the Runtime owner: the Guards run in the Runtime call, i.e. after the
model has already seen the document and chosen a tool. That is the placement the
current Runtime supports; it does not stop a model from being influenced, it stops
the resulting tool call and output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from runtime.adapter import RuntimeAdapter
from runtime.dto import RuntimeRequest, ToolRequest
from runtime.mock_tools.tools import MockReadFile, MockSendEmail

SYSTEM_PROMPT = (
    "You are a document assistant. Use the document as reference material only. "
    "You may request at most one tool call: read_file(path) or send_email(to, subject, body)."
)

TOOL_SPECS: list[dict[str, Any]] = [
    {"name": "read_file", "description": "Read a document by path.", "parameters": {"path": "string"}},
    {"name": "send_email", "description": "Send an email (simulated).",
     "parameters": {"to": "list[string]", "subject": "string", "body": "string"}},
]


@dataclass(frozen=True)
class ToolIntent:
    tool_name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class LLMReply:
    text: str = ""
    tool_call: ToolIntent | None = None
    model: str = ""  # recorded for every real-model result (provider/model/version)


class AgentLLM(Protocol):
    def decide(self, system: str, user_input: str, context_items: list[str],
               tools: list[dict[str, Any]]) -> LLMReply: ...


@dataclass
class ScriptedLLM:
    """Deterministic stand-in: ``policy(user_input, context_items)`` returns the reply."""

    policy: Any
    model: str = "scripted"
    calls: list[dict[str, Any]] = field(default_factory=list)

    def decide(self, system, user_input, context_items, tools):
        self.calls.append({"user_input": user_input, "context_items": list(context_items)})
        reply = self.policy(user_input, context_items)
        return LLMReply(text=reply.text, tool_call=reply.tool_call, model=self.model)


@dataclass
class AgentRun:
    reply: LLMReply
    runtime_result: Any | None  # RuntimeRunResult, None when the model asked for no tool
    tool_executed: bool
    output_delivered: bool
    decision: str | None


def default_tools(documents: dict[str, str]) -> dict[str, Any]:
    return {"read_file": MockReadFile(documents), "send_email": MockSendEmail()}


def run_agent_task(llm: AgentLLM, task: str, context_items: list[str], *, tools: dict[str, Any],
                   evidence, security_factory, session_id: str = "agent-session",
                   scenario_id: str | None = None) -> AgentRun:
    """Ask the model for a tool intent, then run it through the Runtime."""
    reply = llm.decide(SYSTEM_PROMPT, task, context_items, TOOL_SPECS)
    if reply.tool_call is None:
        return AgentRun(reply, None, tool_executed=False, output_delivered=False, decision=None)

    result = RuntimeAdapter().run(
        RuntimeRequest(
            user_input=task, context_items=context_items, session_id=session_id, scenario_id=scenario_id,
            tool_request=ToolRequest(tool_name=reply.tool_call.tool_name,
                                     tool_arguments=dict(reply.tool_call.arguments)),
        ),
        tools=tools, evidence=evidence, security_factory=security_factory,
    )
    return AgentRun(
        reply, result,
        tool_executed=bool(result.execution and result.execution.executed),
        output_delivered=bool(result.output_allowed),
        decision=result.decision.decision.value if result.decision else None,
    )
