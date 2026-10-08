"""Interactive CLI for the three real integration scenarios."""

import logging

from service import SCENARIOS, guard_rows, query_events, run_scenario

logger = logging.getLogger(__name__)


def main():
    while True:
        print("\n=== Runtime Security Demo ===")
        for key, scenario in SCENARIOS.items():
            print(f"{key}. {scenario['name']}")
        print("q. 종료")
        choice = input("\n시나리오 선택 > ").strip()
        if choice.lower() == "q":
            return
        if choice not in SCENARIOS:
            print("1, 2, 3 또는 q를 입력해주세요.")
            continue

        scenario = SCENARIOS[choice]
        print(f"\nUser Prompt: {scenario['prompt']}")
        print(f"Tool 후보: {scenario['tool']} (Mock)")
        print("실제 Runtime / Security Core 실행 중...")
        try:
            snapshot = run_scenario(choice)
        except Exception as exc:
            logger.exception("Demo operation failed")
            print(f"데모 실행 오류: {type(exc).__name__}: {exc}")
            continue

        result = snapshot["result"]
        run_id = result["identity"]["run_id"]
        try:
            events = query_events(run_id)
        except Exception as exc:
            logger.exception("Demo operation failed")
            events = []
            print(f"Evidence 조회 실패: {type(exc).__name__}: {exc}")

        print("\n--- DB에서 조회한 Guard 결과 ---")
        for row in guard_rows(events):
            print(
                f"{row['단계']:<10} {row['판정']:<10} "
                f"risk={row['위험 점수']} "
                f"status={row['검사 상태']}"
            )

        decision = result.get("decision") or {}
        execution = result.get("execution") or {}
        print("\n--- 실제 실행 결과 ---")
        print("Final Decision :", decision.get("decision", "없음"))
        print("Run Status     :", result["run_status"])
        print("Tool Calls     :", snapshot["tool_calls"])
        print("Execution      :", execution.get("execution_state", "없음"))
        print("Output 전달    :", "허용" if result["output_allowed"] else "차단")
        print("run_id         :", run_id)
        print("trace_id       :", result["identity"]["trace_id"])
        print("Evidence 조회  :", len(events), "건")
        if result["output_allowed"]:
            print("전달된 출력    :", result["forward_output"])
        if result["errors"]:
            print("오류           :", result["errors"])
        print("\nStreamlit에서 목록 새로고침 후 같은 run_id를 선택하세요.")


if __name__ == "__main__":
    main()
