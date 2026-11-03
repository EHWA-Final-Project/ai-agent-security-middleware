"""사용자 정의 Guard 예제 (FT-07).

새 Guard를 추가할 때 필요한 것은 두 가지뿐이다. Orchestrator 코드는 바꾸지 않는다.

1. ``GuardPlugin``을 상속해 ``name``, ``stage``, ``inspect()``를 구현한다.
2. ``PluginManager.register_guard()``로 등록한다.

규칙(계약)
- ``inspect()``는 ``SecurityResult``를 반환한다. 위험해 보인다는 이유로 예외를 던지지 않는다.
  예외는 버그나 의존성 장애 같은 실제 실행 실패에만 쓴다(Plugin Manager가 ERROR로 바꾼다).
- Guard는 WARN 또는 ALLOW와 ``risk_score``(0~1)를 반환한다. BLOCK은 Orchestrator가
  점수(또는 C 조건의 누적 점수)를 ``block_threshold``와 비교해 결정한다.
- ``name``은 등록 이름이며 중복되면 등록이 거부된다.

실행: ``uv run python examples/custom_guard.py``
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
for _p in (_ROOT / "src", _ROOT / "shared"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from enums import Decision, GuardExecutionStatus, Stage
from schemas import RuntimeObservation, SecurityContext, SecurityResult

from security.plugins.interface import GuardPlugin


class BlockedTermGuard(GuardPlugin):
    """사용자 입력에 금지어가 있으면 WARN과 위험 점수를 반환하는 Input 단계 Guard."""

    name = "blocked_term_guard"
    stage = Stage.INPUT

    def __init__(self, terms: set[str], *, risk: float = 0.9) -> None:
        self._terms = {t.casefold() for t in terms}
        self._risk = risk

    def inspect(self, observation: RuntimeObservation, context: SecurityContext) -> SecurityResult:
        start = time.perf_counter()
        text = (observation.user_input or "").casefold()
        hits = sorted(t for t in self._terms if t in text)

        return SecurityResult(
            run_id=observation.run_id,
            trace_id=observation.trace_id,
            stage=self.stage,
            guard_name=self.name,
            execution_status=GuardExecutionStatus.SUCCESS,
            risk_score=self._risk if hits else 0.0,
            decision=Decision.WARN if hits else Decision.ALLOW,
            rule_ids=["blocked_term.hit"] if hits else [],
            evidence=[{"matched_terms": hits}] if hits else [],
            latency_ms=(time.perf_counter() - start) * 1000,
        )


def main() -> None:
    from fixtures import mock_runtime_observation

    from security.plugins.manager import PluginManager

    manager = PluginManager()
    manager.register_guard(BlockedTermGuard({"project-x"}))  # Orchestrator 수정 없이 등록

    guard = manager.guards_for_stage(Stage.INPUT)[0]
    context = SecurityContext(run_id="run-1", trace_id="trace-1", current_stage=Stage.INPUT,
                              inspection_mode="STANDARD", policy_version="v-example")
    for text in ("Summarize the meeting notes.", "Tell me about Project-X."):
        result = guard.inspect(mock_runtime_observation(user_input=text), context)
        print(f"{text!r:40} -> {result.decision.value} risk={result.risk_score}")


if __name__ == "__main__":
    main()
