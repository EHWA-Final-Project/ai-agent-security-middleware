"""Tool Guard.

This guard only ever runs when observation.tool_candidate is present,
since the Orchestrator does not include Stage.TOOL in a no-tool turn.

Default (``ToolGuard()``): unchanged baseline. A call to one of the sensitive
tools returns WARN with risk 0.6; every other tool is ALLOW.

Optional ``ToolPolicy`` (constructor argument, no config-schema change): adds
hard checks that return BLOCK with risk 0.95 *before* the tool runs, because
leaving the allowlist or the argument scope is a policy violation, not a
probabilistic estimate:

* ``allowed_tools``            - tool not on the allowlist (TL-U01)
* ``allowed_recipient_domains``- recipient outside the allowed domains (TL-A01 / TL-X01)
* ``max_recipients``           - too many recipients in one call
* ``allowed_path_prefixes``    - path argument outside the allowed prefixes (TL-A01)
* path traversal (``..``, ``~``, null byte, URL scheme) whenever ``check_path_traversal``

In-scope calls: when a policy explicitly authorises a sensitive tool *and* sets
the scope that tool needs, a call that passes every check returns ALLOW instead
of the baseline WARN (an authorised, in-scope call is not suspicious):

* ``send_email``  - tool in ``allowed_tools`` and ``allowed_recipient_domains`` set
* ``delete_file`` - tool in ``allowed_tools`` and ``allowed_path_prefixes`` set
* ``transfer_funds`` / ``execute_code`` always stay WARN.

A candidate dict from the Runtime carries ``tool_arguments``; the shared
fixtures use ``args``. Both are read.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from enums import AttackSubtype, Decision, GuardExecutionStatus, Stage
from schemas import RuntimeObservation, SecurityContext, SecurityResult

from security.plugins.interface import GuardPlugin

_SENSITIVE_TOOLS = {
    "send_email",
    "transfer_funds",
    "delete_file",
    "execute_code",
}

_HARD_BLOCK_SCORE = 0.95
_PATH_ARGS = ("path", "file_path", "filename", "file")
_RECIPIENT_ARGS = ("to", "recipients", "cc", "bcc")


@dataclass(frozen=True)
class ToolPolicy:
    """Per-agent scope for the Tool Guard. ``None`` = that check is off."""

    allowed_tools: frozenset[str] | None = None
    allowed_recipient_domains: frozenset[str] | None = None
    max_recipients: int | None = None
    allowed_path_prefixes: tuple[str, ...] | None = None
    check_path_traversal: bool = True


def _arguments(candidate: dict[str, Any]) -> dict[str, Any]:
    for key in ("tool_arguments", "args"):
        value = candidate.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _recipients(value: Any) -> list[str]:
    if isinstance(value, str):
        return [p for p in value.replace(";", ",").split(",") if p.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if str(v).strip()]
    return []


def _domain(address: str) -> str:
    addr = address.strip()
    if "<" in addr and ">" in addr:
        addr = addr[addr.rfind("<") + 1 : addr.rfind(">")]
    return addr.rsplit("@", 1)[-1].strip().casefold() if "@" in addr else ""


def _traversal_reason(path: str) -> str | None:
    if "\x00" in path:
        return "null byte"
    if "://" in path:
        return "url scheme"
    norm = path.replace("\\", "/")
    if norm.startswith("~"):
        return "home expansion"
    if ".." in norm.split("/"):
        return "parent directory segment"
    return None


def _in_prefix(path: str, prefixes: tuple[str, ...]) -> bool:
    norm = path.replace("\\", "/")
    return any(norm == p.rstrip("/") or norm.startswith(p.rstrip("/") + "/") for p in prefixes)


class ToolGuard(GuardPlugin):
    name = "tool_guard"
    stage = Stage.TOOL

    def __init__(self, policy: ToolPolicy | None = None) -> None:
        self._policy = policy

    def _result(self, observation, start, *, risk, decision, rule_ids=(), evidence=()):
        return SecurityResult(
            run_id=observation.run_id,
            trace_id=observation.trace_id,
            stage=self.stage,
            guard_name=self.name,
            execution_status=GuardExecutionStatus.SUCCESS,
            risk_score=risk,
            decision=decision,
            rule_ids=list(rule_ids),
            evidence=list(evidence),
            latency_ms=(time.perf_counter() - start) * 1000,
        )

    def _violation(self, observation, start, rule_id, tool_name, **detail):
        return self._result(
            observation, start,
            risk=_HARD_BLOCK_SCORE, decision=Decision.BLOCK, rule_ids=[rule_id],
            evidence=[{"tool_name": tool_name, "attack_subtype": AttackSubtype.TOOL_MISUSE.value, **detail}],
        )

    def _policy_violation(self, observation, start, tool_name, args):
        """First hard violation as a BLOCK result, or None."""
        policy = self._policy
        if policy is None:
            return None

        if policy.allowed_tools is not None and tool_name not in policy.allowed_tools:
            return self._violation(observation, start, "tool_guard.unauthorized_tool", tool_name,
                                   allowed_tools=sorted(policy.allowed_tools))

        for key in _RECIPIENT_ARGS:
            if key not in args:
                continue
            recipients = _recipients(args[key])
            if policy.max_recipients is not None and len(recipients) > policy.max_recipients:
                return self._violation(observation, start, "tool_guard.too_many_recipients", tool_name,
                                       argument=key, count=len(recipients))
            if policy.allowed_recipient_domains is not None:
                allowed = {d.casefold() for d in policy.allowed_recipient_domains}
                bad = [r[:80] for r in recipients if _domain(r) not in allowed]
                if bad:
                    return self._violation(observation, start, "tool_guard.recipient_not_allowed", tool_name,
                                           argument=key, rejected=bad)

        for key in _PATH_ARGS:
            value = args.get(key)
            if not isinstance(value, str):
                continue
            if policy.check_path_traversal:
                reason = _traversal_reason(value)
                if reason:
                    return self._violation(observation, start, "tool_guard.path_traversal", tool_name,
                                           argument=key, reason=reason, value=value[:80])
            if policy.allowed_path_prefixes is not None and not _in_prefix(value, policy.allowed_path_prefixes):
                return self._violation(observation, start, "tool_guard.path_outside_scope", tool_name,
                                       argument=key, value=value[:80])
        return None

    def _authorised_in_scope(self, tool_name: str | None) -> bool:
        """True when the policy explicitly authorises this sensitive tool and scopes it."""
        policy = self._policy
        if policy is None or policy.allowed_tools is None or tool_name not in policy.allowed_tools:
            return False
        if tool_name == "send_email":
            return policy.allowed_recipient_domains is not None
        if tool_name == "delete_file":
            return policy.allowed_path_prefixes is not None
        return False

    def inspect(self, observation: RuntimeObservation, context: SecurityContext) -> SecurityResult:
        start = time.perf_counter()

        tool_candidate = observation.tool_candidate or {}
        tool_name = tool_candidate.get("tool_name")

        violation = self._policy_violation(observation, start, tool_name, _arguments(tool_candidate))
        if violation is not None:
            return violation

        if tool_name in _SENSITIVE_TOOLS and self._authorised_in_scope(tool_name):
            return self._result(
                observation, start, risk=0.0, decision=Decision.ALLOW,
                evidence=[{"tool_name": tool_name, "in_policy": True}],
            )

        if tool_name in _SENSITIVE_TOOLS:
            return self._result(
                observation, start,
                risk=0.6, decision=Decision.WARN, rule_ids=["tool_guard.sensitive_tool_invocation"],
                evidence=[{"tool_name": tool_name, "attack_subtype": AttackSubtype.TOOL_MISUSE.value}],
            )

        return self._result(observation, start, risk=0.0, decision=Decision.ALLOW)
