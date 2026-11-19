"""G1-style check for ``server/tool`` names through Runtime, under B and C.

The Host Adapter will strip the server before calling the MCP server. The
``_Qualified`` wrapper below plays that role for the Mock tools: the Runtime
and Guards see ``demo/read_file``, the Mock tool sees ``read_file``.
Sanitize/redaction through ``select_output`` is Runtime's part and is not
covered here.
"""

import pytest
from enums import Decision, RunStatus

from evidence.collector import EvidenceCollector
from evidence.sqlite_repository import SQLiteEvidenceRepository
from runtime.adapter import RuntimeAdapter
from runtime.dto import RuntimeRequest, ToolCandidate, ToolRequest
from runtime.mock_tools.tools import MockReadFile, MockSendEmail
from security.plugins.guards.tool_guard import ToolPolicy
from security.policy.conditions import load_condition, make_condition_security_factory

POLICY = ToolPolicy(
    allowed_tools=frozenset({"demo/read_file", "demo/send_email"}),
    allowed_recipient_domains=frozenset({"corp.com"}),
    allowed_path_prefixes=("docs",),
)


class _Qualified:
    """Adapter stand-in: strip ``server/`` and delegate to a Mock tool."""

    def __init__(self, inner) -> None:
        self._inner = inner

    def execute(self, candidate: ToolCandidate):
        base = candidate.tool_name.rsplit("/", 1)[-1]
        return self._inner.execute(candidate.model_copy(update={"tool_name": base}))


def _run(tmp_path, name, tool_request, policy=POLICY):
    repository = SQLiteEvidenceRepository(tmp_path / f"{name}.db")
    collector = EvidenceCollector(repository)
    read_file = MockReadFile({"docs/a.txt": "hello", "secrets/k.txt": "key"})
    send_email = MockSendEmail()
    result = RuntimeAdapter().run(
        RuntimeRequest(user_input="Summarize the document.", context_items=[], session_id=f"s-{name}",
                       scenario_id="MCP", tool_request=tool_request),
        tools={"demo/read_file": _Qualified(read_file), "demo/send_email": _Qualified(send_email),
               "evil/read_file": _Qualified(read_file), "evil/send_email": _Qualified(send_email)},
        evidence=collector,
        security_factory=make_condition_security_factory(load_condition(name), collector, tool_policy=policy),
    )
    return result, read_file, send_email


def _req(tool, **args):
    return ToolRequest(tool_name=tool, tool_arguments=args)


@pytest.mark.parametrize("name", ["B", "C"])
def test_allowed_qualified_read_runs_and_output_is_forwarded(tmp_path, name):
    result, read_file, _ = _run(tmp_path, name, _req("demo/read_file", path="docs/a.txt"))
    assert result.run_status == RunStatus.COMPLETED
    assert result.decision.decision == Decision.ALLOW and read_file.call_count == 1
    assert result.output_allowed is True and result.forward_output["content"] == "hello"


@pytest.mark.parametrize("name", ["B", "C"])
def test_allowed_qualified_email_in_scope_runs(tmp_path, name):
    result, _, send_email = _run(
        tmp_path, name, _req("demo/send_email", to=["a@corp.com"], subject="s", body="b"))
    assert result.decision.decision == Decision.ALLOW and send_email.call_count == 1


@pytest.mark.parametrize("name", ["B", "C"])
@pytest.mark.parametrize(
    "request_",
    [
        _req("evil/read_file", path="docs/a.txt"),  # same tool, other server
        _req("evil/send_email", to=["a@corp.com"], subject="s", body="b"),
        _req("demo/send_email", to=["leak@evil.com"], subject="s", body="b"),  # recipient out of scope
        _req("demo/read_file", path="secrets/k.txt"),  # path out of scope
    ],
)
def test_unauthorized_qualified_calls_are_blocked_with_zero_calls(tmp_path, name, request_):
    result, read_file, send_email = _run(tmp_path, name, request_)
    assert result.decision.decision == Decision.BLOCK and result.execution.executed is False
    assert read_file.call_count == 0 and send_email.call_count == 0
    assert result.output_allowed is False


@pytest.mark.parametrize("name", ["B", "C"])
def test_qualified_call_without_policy_is_blocked_with_zero_calls(tmp_path, name):
    result, read_file, _ = _run(tmp_path, name, _req("demo/read_file", path="docs/a.txt"), policy=None)
    assert result.decision.decision == Decision.BLOCK and result.execution.executed is False
    assert read_file.call_count == 0
