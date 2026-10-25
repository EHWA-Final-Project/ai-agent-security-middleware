"""조건 A / B / C 반복 실행으로 latency 측정 (프로토타입).

실행: uv run python examples/measure_latency.py --repeat 200 --seed 0 --out latency.jsonl

측정 범위 (모두 SecurityOrchestrator.last_timing 기준, 단위 ms):
  security_core_ms  Guard 시간을 포함한 Security Core 전체 (evaluate 전체에서 Tool 실행·Evidence 기록 시간을 뺀 값)
  core_excluding_guard_ms  Guard를 제외한 나머지 Core 시간 (= security_core_ms - guard_wall_ms)
  guard_wall_ms     Orchestrator가 Guard 호출마다 잰 시간의 합 (thread 전달 시간 포함, A는 0)
  guard_ms          Guard가 스스로 보고한 SecurityResult.latency_ms 합계 (A는 0)
  evaluate_ms       evaluate() 전체 시간 (참고용: Tool 실행·Evidence 기록 포함)
Evidence는 메모리 sink를 사용하므로 SQLite 쓰기 시간은 거의 들어가지 않습니다.

측정 범위 밖 (이 스크립트가 보여주지 않는 것):
- Runtime end-to-end latency는 Runtime(RuntimeAdapter) 쪽 측정 대상입니다. 여기서는 SecurityOrchestrator를
  직접 호출하고, Enforcement는 가짜(_Enforcement)라 실제 Tool 실행 시간이 없습니다.
- 공식 p50/p95 집계는 Evaluation 파이프라인 담당입니다. 여기 percentile은 raw 기록이 충분한지 확인하는 용도입니다.
- 기본 baseline(block_threshold=0.80)에서 B/C의 결정은 같지만 C는 누적 점수를 계산하므로 시간은 다를 수 있습니다.

- 실행 순서는 --seed로 섞어 고정합니다 (같은 seed면 같은 순서). 앞 단계 warm-up은 결과에서 제외합니다.
- 기본은 run마다 Orchestrator를 새로 만듭니다 (runtime의 run_connected와 같은 방식, 현재 의도된 설계).
  Orchestrator와 thread pool 객체를 만드는 시간은 측정 범위 밖입니다 (evaluate 호출 전에 끝남).
  다만 첫 Guard 호출 때 worker thread를 시작하는 비용은 guard_wall_ms에 포함됩니다.
  --reuse-orchestrator (별도 비교용)는 시나리오별 하나를 재사용하므로 이 시작 비용이 빠집니다.
- 모든 run의 원자료를 --out(JSONL)에 남기고, 실행 조건(재사용 여부, seed, warmup, repeat, 환경)은
  같은 위치의 <out>.meta.json에 함께 남깁니다. percentile은 JSONL에서 계산하세요.
- 결과 숫자는 실행 환경에 따라 달라지므로 A/B/C는 같은 환경에서 함께 측정해야 합니다.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import sys
from datetime import UTC, datetime
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
for _p in (_ROOT / "src", _ROOT / "shared", Path(__file__).resolve().parent):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from compare_modes import SCENARIOS, _Enforcement
from fixtures import mock_runtime_observation

from security.measurement import summarize
from security.orchestrator.orchestrator import SecurityOrchestrator
from security.policy.conditions import (
    CONDITION_FILES,
    Condition,
    build_plugin_manager,
    load_condition,
)


class _Sink:
    def __init__(self) -> None:
        self.results: list = []

    def record_result(self, result) -> None:
        self.results.append(result)

    def record_decision(self, decision) -> None:
        pass


def _observation(scenario):
    _, user_input, context_items, tool_name, _ = scenario
    observation = mock_runtime_observation(
        user_input=user_input,
        tool_candidate={"tool_call_id": "call-1", "tool_name": tool_name, "tool_arguments": {}},
    )
    observation.context_items = context_items
    return observation


def _measure(orchestrator, enforcement, sink, scenario, condition: Condition, repetition: int) -> dict:
    sink.results.clear()
    observation = _observation(scenario)
    decision = orchestrator.evaluate(observation)
    timing = orchestrator.last_timing
    return {
        "condition": condition.name,
        "policy_version": decision.policy_version,
        "scenario_id": scenario[0],
        "repetition": repetition,
        "decision": decision.decision.value,
        "tool_ran": enforcement.tool_ran,
        "security_core_ms": timing.security_core_ms,
        "guard_wall_ms": timing.guard_wall_total_ms,
        "core_excluding_guard_ms": timing.security_core_ms - timing.guard_wall_total_ms,
        "guard_ms": sum(r.latency_ms for r in sink.results),
        "evaluate_ms": timing.evaluate_ms,
        "enforcement_ms": timing.enforcement_ms,
        "evidence_ms": timing.evidence_ms,
        "guard_count": len(sink.results),
    }


def collect(conditions, repeat: int, warmup: int, seed: int, reuse: bool) -> list[dict]:
    jobs = [(c, s, i) for c in conditions for s in SCENARIOS for i in range(warmup + repeat)]
    random.Random(seed).shuffle(jobs)

    shared = {}
    records, seen = [], {}
    for condition, scenario, i in jobs:
        key = (condition.name, scenario[0])
        enforcement, sink = _Enforcement(scenario[3], scenario[4]), _Sink()
        orchestrator = None
        if reuse:
            if key not in shared:
                shared[key] = (
                    SecurityOrchestrator(
                        build_plugin_manager(condition), condition.policy, enforcement, sink,
                    ),
                    enforcement,
                    sink,
                )
            orchestrator, enforcement, sink = shared[key]
        else:
            orchestrator = SecurityOrchestrator(
                build_plugin_manager(condition), condition.policy, enforcement, sink,
            )
        try:
            seen[key] = seen.get(key, 0) + 1
            record = _measure(orchestrator, enforcement, sink, scenario, condition, seen[key])
        finally:
            if not reuse:
                orchestrator.close()
        if seen[key] > warmup:
            record["repetition"] = seen[key] - warmup
            records.append(record)
    for orchestrator, _, _ in shared.values():
        orchestrator.close()
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repeat", type=int, default=200, help="measured runs per (condition, scenario)")
    parser.add_argument("--warmup", type=int, default=10, help="discarded runs per (condition, scenario)")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--block-threshold", type=float, default=None)
    parser.add_argument("--reuse-orchestrator", action="store_true")
    parser.add_argument("--out", type=Path, default=None, help="write raw per-run records as JSONL")
    args = parser.parse_args()

    conditions = [load_condition(n, block_threshold=args.block_threshold) for n in CONDITION_FILES]
    records = collect(conditions, args.repeat, args.warmup, args.seed, args.reuse_orchestrator)

    if args.out:
        args.out.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n", encoding="utf-8")
        meta_path = args.out.with_name(args.out.name + ".meta.json")
        meta = {
            "created_at": datetime.now(UTC).isoformat(),
            "reuse_orchestrator": args.reuse_orchestrator,
            "seed": args.seed,
            "warmup": args.warmup,
            "repeat": args.repeat,
            "block_threshold_override": args.block_threshold,
            "conditions": {c.name: c.policy.policy_version for c in conditions},
            "records": len(records),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "cpu_count": os.cpu_count(),
        }
        meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"raw records: {len(records)} -> {args.out} (metadata: {meta_path})")

    print(
        f"repeat={args.repeat} warmup={args.warmup} seed={args.seed} "
        f"reuse_orchestrator={args.reuse_orchestrator} block_threshold={conditions[0].policy.block_threshold}"
    )
    print(f"\n{'condition':<10} {'metric':<25} {'n':>6} {'avg':>9} {'p50':>9} {'p95':>9} {'max':>9}   (ms)")
    for c in conditions:
        mine = [r for r in records if r["condition"] == c.name]
        for metric in ("security_core_ms", "core_excluding_guard_ms", "guard_wall_ms", "guard_ms", "evaluate_ms"):
            s = summarize([r[metric] for r in mine])
            print(
                f"{c.name:<10} {metric:<25} {int(s['n']):>6} {s['avg']:>9.4f} "
                f"{s['p50']:>9.4f} {s['p95']:>9.4f} {s['max']:>9.4f}"
            )


if __name__ == "__main__":
    main()
