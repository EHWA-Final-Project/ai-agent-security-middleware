"""Tool Guard behavior for MCP ``server/tool`` names (e.g. ``demo/read_file``).

Rules under test:
* Sensitive-tool classification and scope use the base name.
* ``allowed_tools`` is matched on the full name, so the same tool on another
  server is never allowed by accident.
* A ``server/tool`` call without an allowlist policy is denied by default.
* Bare names keep their existing behavior (covered by test_tool_guard*.py).
"""

import pytest
from enums import Decision, InspectionMode, Stage
from fixtures import mock_runtime_observation
from schemas import SecurityContext

from security.plugins.guards.tool_guard import ToolGuard, ToolPolicy

POLICY = ToolPolicy(
    allowed_tools=frozenset({"demo/read_file", "demo/send_email"}),
    allowed_recipient_domains=frozenset({"corp.com"}),
    allowed_path_prefixes=("docs",),
)


def _ctx() -> SecurityContext:
    return SecurityContext(run_id="run-1", trace_id="trace-1", current_stage=Stage.TOOL,
                           inspection_mode=InspectionMode.STANDARD, policy_version="v-test")


def _inspect(guard, tool_name, **args):
    obs = mock_runtime_observation(tool_candidate={"tool_name": tool_name, "tool_arguments": args})
    return guard.inspect(obs, _ctx())


def test_allowed_qualified_calls_in_scope_are_allowed():
    guard = ToolGuard(POLICY)
    assert _inspect(guard, "demo/read_file", path="docs/a.txt").decision == Decision.ALLOW
    sent = _inspect(guard, "demo/send_email", to=["a@corp.com"], subject="s", body="b")
    assert sent.decision == Decision.ALLOW and sent.risk_score == 0.0
    assert sent.evidence[0]["tool_name"] == "demo/send_email"


@pytest.mark.parametrize("tool", ["evil/read_file", "evil/send_email", "demo/delete_file", "read_file"])
def test_same_name_on_another_server_or_unlisted_tool_is_blocked(tool):
    r = _inspect(ToolGuard(POLICY), tool, path="docs/a.txt", to=["a@corp.com"])
    assert r.decision == Decision.BLOCK and r.risk_score == 0.95
    assert r.rule_ids == ["tool_guard.unauthorized_tool"]


def test_qualified_sensitive_tool_gets_the_same_checks_as_the_bare_name():
    guard = ToolGuard(POLICY)
    # recipient scope still applies through the server prefix
    out = _inspect(guard, "demo/send_email", to=["leak@evil.com"], subject="s", body="b")
    assert out.decision == Decision.BLOCK and out.rule_ids == ["tool_guard.recipient_not_allowed"]
    # required argument still enforced
    missing = _inspect(guard, "demo/send_email", subject="s", body="b")
    assert missing.decision == Decision.BLOCK and missing.rule_ids == ["tool_guard.invalid_arguments"]
    # path scope and traversal still enforced for read_file
    assert _inspect(guard, "demo/read_file", path="secrets/k.txt").rule_ids == ["tool_guard.path_outside_scope"]
    assert _inspect(guard, "demo/read_file", path="docs/../k.txt").rule_ids == ["tool_guard.path_traversal"]


def test_qualified_sensitive_tool_is_warned_when_allowed_but_not_scoped():
    # allowlisted, but no recipient scope configured -> not downgraded to ALLOW
    guard = ToolGuard(ToolPolicy(allowed_tools=frozenset({"demo/send_email"})))
    r = _inspect(guard, "demo/send_email", to=["a@corp.com"], subject="s", body="b")
    assert r.decision == Decision.WARN and r.risk_score == 0.6
    assert r.rule_ids == ["tool_guard.sensitive_tool_invocation"]


@pytest.mark.parametrize("policy", [None, ToolPolicy(), ToolPolicy(max_recipients=3)])
@pytest.mark.parametrize("tool", ["demo/read_file", "demo/send_email", "demo/anything"])
def test_qualified_call_without_allowlist_is_denied_by_default(policy, tool):
    r = _inspect(ToolGuard(policy), tool, path="docs/a.txt", to=["a@corp.com"])
    assert r.decision == Decision.BLOCK and r.risk_score == 0.95
    assert r.rule_ids == ["tool_guard.mcp_policy_missing"]
    assert r.evidence[0]["tool_name"] == tool


def test_bare_names_are_unchanged_without_a_policy():
    guard = ToolGuard()
    assert _inspect(guard, "read_file", path="../../etc/passwd").decision == Decision.ALLOW
    r = _inspect(guard, "send_email", to=["x@evil.com"])
    assert r.decision == Decision.WARN and r.risk_score == 0.6


def test_bare_allowlist_does_not_allow_a_qualified_name():
    guard = ToolGuard(ToolPolicy(allowed_tools=frozenset({"read_file", "send_email"})))
    r = _inspect(guard, "evil/send_email", to=["a@corp.com"])
    assert r.decision == Decision.BLOCK and r.rule_ids == ["tool_guard.unauthorized_tool"]
