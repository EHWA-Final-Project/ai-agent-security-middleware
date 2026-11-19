"""Tool Guard.

``observation.tool_candidate``가 있을 때만 실행된다(Tool 호출이 없는 턴에는
Orchestrator가 Stage.TOOL을 넣지 않는다).

기본(``ToolGuard()``): 기존 동작 그대로이다. 민감 Tool 호출은 WARN(위험 0.6),
그 외 Tool은 ALLOW이다.

선택 ``ToolPolicy``(생성자 인자, 설정 스키마 변경 없음): Tool 실행 **전에** BLOCK
(위험 0.95)을 반환하는 검사를 추가한다. allowlist나 인자 범위를 벗어나는 것은
확률 추정이 아니라 정책 위반이기 때문이다.

* ``allowed_tools``             - allowlist에 없는 Tool (TL-U01)
* ``allowed_recipient_domains`` - 허용 도메인 밖의 수신자 (TL-A01 / TL-X01)
* ``max_recipients``            - 한 번에 너무 많은 수신자 (to + cc + bcc 합계 기준)
* 인자 형식 오류                 - 잘못된 타입, 또는 범위 안 호출에서 필수 인자 누락
* ``allowed_path_prefixes``     - 허용 prefix 밖의 경로 (TL-A01)
* 경로 우회(``..``, ``~``, null 바이트, URL 스킴): ``check_path_traversal``이 켜져 있으면 검사

범위 안의 호출: 정책이 민감 Tool을 명시적으로 허용하고 그 Tool에 필요한 범위도
설정했으며 모든 검사를 통과하면, 기본 WARN 대신 ALLOW를 반환한다.

* ``send_email``  - ``allowed_tools``와 ``allowed_recipient_domains`` 설정 필요
* ``delete_file`` - ``allowed_tools``와 ``allowed_path_prefixes`` 설정 필요
* ``transfer_funds`` / ``execute_code``는 항상 WARN을 유지한다.

MCP ``server/tool`` 이름(예: ``demo/send_email``):

* 민감 Tool 판별과 범위 판정은 base 이름(``send_email``)으로 한다.
* ``allowed_tools`` 소속 확인은 전체 이름으로 한다. 다른 서버의 같은 이름 Tool은
  허용되지 않는다.
* 정책이 없거나 ``allowed_tools``가 없으면 ``server/tool`` 호출은 기본 거부(BLOCK)한다.

Runtime의 candidate dict는 ``tool_arguments``를, 공용 fixture는 ``args``를 쓰며
둘 다 읽는다.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from enums import AttackSubtype, Decision, GuardExecutionStatus, Stage
from schemas import RuntimeObservation, SecurityContext, SecurityResult

from security.plugins.guards._tool_names import base_tool_name, is_qualified
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


def _split_addresses(text: str) -> list[str]:
    return [p.strip() for p in text.replace(";", ",").split(",") if p.strip()]


def _recipients(value: Any) -> list[str] | None:
    """값 안의 모든 주소를 하나씩 반환한다. 타입이 잘못되면 ``None``.

    리스트의 한 원소에 여러 주소가 들어 있을 수 있다("a@x.com, b@y.com").
    원소도 쉼표·세미콜론으로 나눠야 허용되지 않은 도메인이 한 원소 안에
    숨어 검증을 우회하지 못한다.
    """
    if isinstance(value, str):
        return _split_addresses(value)
    if isinstance(value, (list, tuple, set)):
        out: list[str] = []
        for item in value:
            if not isinstance(item, str):
                return None
            out.extend(_split_addresses(item))
        return out
    return None


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

        checks_recipients = policy.max_recipients is not None or policy.allowed_recipient_domains is not None
        if checks_recipients:
            per_key: dict[str, list[str]] = {}
            for key in _RECIPIENT_ARGS:
                if key not in args:
                    continue
                recipients = _recipients(args[key])
                if recipients is None:
                    return self._violation(observation, start, "tool_guard.invalid_arguments", tool_name,
                                           argument=key, reason="wrong type")
                per_key[key] = recipients

            # 제한은 필드별이 아니라 to + cc + bcc(+ recipients) 합계에 건다.
            total = sum(len(v) for v in per_key.values())
            if policy.max_recipients is not None and total > policy.max_recipients:
                return self._violation(observation, start, "tool_guard.too_many_recipients", tool_name,
                                       count=total, limit=policy.max_recipients)
            if policy.allowed_recipient_domains is not None:
                allowed = {d.casefold() for d in policy.allowed_recipient_domains}
                for key, recipients in per_key.items():
                    bad = [r[:80] for r in recipients if _domain(r) not in allowed]
                    if bad:
                        return self._violation(observation, start, "tool_guard.recipient_not_allowed", tool_name,
                                               argument=key, rejected=bad)

        for key in _PATH_ARGS:
            if key not in args:
                continue
            value = args[key]
            if not isinstance(value, str):
                return self._violation(observation, start, "tool_guard.invalid_arguments", tool_name,
                                       argument=key, reason="wrong type")
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
        base = base_tool_name(tool_name)
        if base == "send_email":
            return policy.allowed_recipient_domains is not None
        if base == "delete_file":
            return policy.allowed_path_prefixes is not None
        return False

    @staticmethod
    def _missing_required(tool_name: str | None, args: dict[str, Any]) -> str | None:
        """범위 안 호출에서 빠진 필수 인자 이름, 없으면 None.

        잘못된 타입은 ``_policy_violation``에서 이미 걸러진다. 여기서는
        인자가 없거나 비어 있는 경우를 잡아 ``in_policy``로 처리되지 않게 한다.
        """
        if tool_name == "send_email":
            has_to = any(_recipients(args.get(k)) for k in ("to", "recipients"))
            return None if has_to else "to"
        if tool_name == "delete_file":
            has_path = any(isinstance(args.get(k), str) and args[k].strip() for k in _PATH_ARGS)
            return None if has_path else "path"
        return None

    def inspect(self, observation: RuntimeObservation, context: SecurityContext) -> SecurityResult:
        start = time.perf_counter()

        tool_candidate = observation.tool_candidate or {}
        tool_name = tool_candidate.get("tool_name")
        base_name = base_tool_name(tool_name)

        # MCP(server/tool) 호출은 기본 거부: 허용 목록(정책)이 없으면 실행하지 않는다.
        if is_qualified(tool_name) and (self._policy is None or self._policy.allowed_tools is None):
            return self._violation(observation, start, "tool_guard.mcp_policy_missing", tool_name,
                                   reason="qualified tool name requires an allowlist policy")

        violation = self._policy_violation(observation, start, tool_name, _arguments(tool_candidate))
        if violation is not None:
            return violation

        if base_name in _SENSITIVE_TOOLS and self._authorised_in_scope(tool_name):
            missing = self._missing_required(base_name, _arguments(tool_candidate))
            if missing is not None:
                return self._violation(observation, start, "tool_guard.invalid_arguments", tool_name,
                                       argument=missing, reason="missing required argument")
            return self._result(
                observation, start, risk=0.0, decision=Decision.ALLOW,
                evidence=[{"tool_name": tool_name, "in_policy": True}],
            )

        if base_name in _SENSITIVE_TOOLS:
            return self._result(
                observation, start,
                risk=0.6, decision=Decision.WARN, rule_ids=["tool_guard.sensitive_tool_invocation"],
                evidence=[{"tool_name": tool_name, "attack_subtype": AttackSubtype.TOOL_MISUSE.value}],
            )

        return self._result(observation, start, risk=0.0, decision=Decision.ALLOW)
