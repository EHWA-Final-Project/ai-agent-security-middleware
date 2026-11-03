"""Tool Guard allowlist / argument policy (TL-U01, TL-A01, TL-X01)."""

import pytest
from enums import Decision, InspectionMode, Stage
from fixtures import mock_runtime_observation
from schemas import SecurityContext

from security.plugins.guards.tool_guard import ToolGuard, ToolPolicy


def _ctx() -> SecurityContext:
    return SecurityContext(run_id="run-1", trace_id="trace-1", current_stage=Stage.TOOL,
                           inspection_mode=InspectionMode.STANDARD, policy_version="v-test")


def _inspect(guard, tool_name, **args):
    # Runtime shape ("tool_arguments") and fixture shape ("args") must both work.
    obs = mock_runtime_observation(tool_candidate={"tool_name": tool_name, "tool_arguments": args})
    return guard.inspect(obs, _ctx())


def test_default_guard_is_unchanged():
    guard = ToolGuard()
    assert _inspect(guard, "read_file", path="../../etc/passwd").decision == Decision.ALLOW
    r = _inspect(guard, "send_email", to=["x@evil.com"])
    assert r.decision == Decision.WARN and r.risk_score == 0.6


def test_unauthorized_tool_is_blocked_before_execution():
    guard = ToolGuard(ToolPolicy(allowed_tools=frozenset({"read_file"})))
    r = _inspect(guard, "send_email", to=["a@corp.com"])
    assert r.decision == Decision.BLOCK and r.risk_score == 0.95
    assert r.rule_ids == ["tool_guard.unauthorized_tool"]
    assert r.evidence[0]["attack_subtype"] == "TOOL_MISUSE"


def test_allowlisted_tool_passes_and_sensitive_without_scope_still_warns():
    guard = ToolGuard(ToolPolicy(allowed_tools=frozenset({"read_file", "send_email"})))
    assert _inspect(guard, "read_file", path="notes.txt").decision == Decision.ALLOW
    # allowlisted but no recipient scope configured -> not downgraded
    assert _inspect(guard, "send_email", to=["a@corp.com"]).decision == Decision.WARN


def test_recipient_outside_allowed_domains_is_blocked():
    guard = ToolGuard(ToolPolicy(allowed_recipient_domains=frozenset({"corp.com"})))
    # domain scope set but the tool is not on an allowlist -> baseline WARN, no downgrade
    assert _inspect(guard, "send_email", to=["a@corp.com"]).decision == Decision.WARN
    r = _inspect(guard, "send_email", to=["a@corp.com", "leak@evil.com"])
    assert r.decision == Decision.BLOCK and r.rule_ids == ["tool_guard.recipient_not_allowed"]
    assert r.evidence[0]["rejected"] == ["leak@evil.com"]


@pytest.mark.parametrize("address", ["x@corp.com.evil.com", "corp.com@evil.com", "Bob <bob@evil.com>", "no-at-sign"])
def test_lookalike_recipients_are_rejected(address):
    guard = ToolGuard(ToolPolicy(allowed_recipient_domains=frozenset({"corp.com"})))
    assert _inspect(guard, "send_email", to=[address]).decision == Decision.BLOCK


def test_recipient_domain_match_is_case_insensitive_and_handles_display_name():
    guard = ToolGuard(ToolPolicy(allowed_recipient_domains=frozenset({"Corp.com"})))
    assert _inspect(guard, "send_email", to=["Bob <BOB@CORP.COM>"]).decision == Decision.WARN  # no downgrade (no allowlist)
    scoped = ToolGuard(ToolPolicy(allowed_tools=frozenset({"send_email"}),
                                  allowed_recipient_domains=frozenset({"Corp.com"})))
    assert _inspect(scoped, "send_email", to=["Bob <BOB@CORP.COM>"]).decision == Decision.ALLOW


def test_too_many_recipients_blocked():
    guard = ToolGuard(ToolPolicy(max_recipients=1))
    r = _inspect(guard, "send_email", to=["a@x.com", "b@x.com"])
    assert r.rule_ids == ["tool_guard.too_many_recipients"]


@pytest.mark.parametrize("path", ["../secret.txt", "docs/../../etc/passwd", "~/.ssh/id_rsa",
                                  "file:///etc/passwd", "a\x00b", "..\\windows\\system32"])
def test_path_traversal_blocked_when_policy_present(path):
    guard = ToolGuard(ToolPolicy())
    r = _inspect(guard, "read_file", path=path)
    assert r.decision == Decision.BLOCK and r.rule_ids == ["tool_guard.path_traversal"]


def test_path_outside_allowed_prefix_blocked_inside_allowed():
    guard = ToolGuard(ToolPolicy(allowed_path_prefixes=("docs",)))
    assert _inspect(guard, "read_file", path="docs/report.txt").decision == Decision.ALLOW
    assert _inspect(guard, "read_file", path="docs").decision == Decision.ALLOW
    r = _inspect(guard, "read_file", path="secrets/key.txt")
    assert r.rule_ids == ["tool_guard.path_outside_scope"]
    assert _inspect(guard, "read_file", path="docs-private/x.txt").decision == Decision.BLOCK


def test_fixture_shape_args_key_is_also_checked():
    guard = ToolGuard(ToolPolicy(allowed_recipient_domains=frozenset({"corp.com"})))
    obs = mock_runtime_observation(tool_candidate={"tool_name": "send_email", "args": {"to": ["x@evil.com"]}})
    assert guard.inspect(obs, _ctx()).decision == Decision.BLOCK


# --- authorised, in-scope sensitive calls are not suspicious (FPR)
def test_authorised_in_scope_send_email_is_allowed_and_traceable():
    guard = ToolGuard(ToolPolicy(allowed_tools=frozenset({"send_email"}),
                                 allowed_recipient_domains=frozenset({"corp.com"})))
    r = _inspect(guard, "send_email", to=["a@corp.com"])
    assert r.decision == Decision.ALLOW and r.risk_score == 0.0
    assert r.evidence == [{"tool_name": "send_email", "in_policy": True}]


def test_authorised_send_email_to_outside_domain_still_blocked():
    guard = ToolGuard(ToolPolicy(allowed_tools=frozenset({"send_email"}),
                                 allowed_recipient_domains=frozenset({"corp.com"})))
    assert _inspect(guard, "send_email", to=["x@evil.com"]).decision == Decision.BLOCK


def test_authorised_delete_file_needs_path_scope_and_stays_in_scope():
    unscoped = ToolGuard(ToolPolicy(allowed_tools=frozenset({"delete_file"})))
    assert _inspect(unscoped, "delete_file", path="tmp/a.txt").decision == Decision.WARN
    scoped = ToolGuard(ToolPolicy(allowed_tools=frozenset({"delete_file"}), allowed_path_prefixes=("tmp",)))
    assert _inspect(scoped, "delete_file", path="tmp/a.txt").decision == Decision.ALLOW
    assert _inspect(scoped, "delete_file", path="docs/a.txt").decision == Decision.BLOCK


@pytest.mark.parametrize("tool", ["transfer_funds", "execute_code"])
def test_other_sensitive_tools_never_downgrade(tool):
    guard = ToolGuard(ToolPolicy(allowed_tools=frozenset({tool}), allowed_recipient_domains=frozenset({"corp.com"}),
                                 allowed_path_prefixes=("tmp",)))
    assert _inspect(guard, tool, amount=5).decision == Decision.WARN
