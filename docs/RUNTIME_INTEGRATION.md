# Runtime / Enforcement 이관 현황

작성자: 지원

## 현재 범위

팀 dev의 Common Baseline을 사용하는 Runtime / Enforcement 구현이다.

- RuntimeObservation 및 ToolCandidate 생성
- 공통 run_id/session_id/trace_id 생성·전파
- tool_call_id 생성·전파
- 실제 SecurityOrchestrator.evaluate() 연결
- Orchestrator가 BoundEnforcement를 통해 Tool 실행·차단
- read_file/send_email Mock Tool
- ExecutionResult 보존 및 Evidence 전달
- 최종 ALLOW와 실행 성공일 때만 후속 출력 전달
- sanitized_output을 read_file의 content에 적용하되 원본 결과는 보존
- 최종 WARN/BLOCK이면 출력 전달 보류
- Evidence 장애 시 Tool 재실행 없이 상태 처리

## 호출 및 전달 책임

RuntimeAdapter.run(request, tools=..., evidence=..., security_factory=...)

- Runtime → Core: RuntimeObservation
- Core → BoundEnforcement: SecurityDecision
- BoundEnforcement → Core: ExecutionResult
- Core → Runtime: 최종 SecurityDecision
- Runtime → Evidence: RuntimeObservation, ExecutionResult, RunStatusUpdate
- Core → Evidence: SecurityResult, 최종 SecurityDecision

Runtime은 evaluate() 반환 후 Enforcement를 다시 호출하지 않는다.

## 검증

팀 공통 환경에서 실행:

    uv sync --frozen
    uv run pytest -q

현재 전체 테스트 102개 통과:
- 기존 Security Core 테스트 64개
- Runtime 단위 테스트 23개
- Runtime 연결 테스트 15개

지원 변경 파일 Ruff 검사 통과.

전체 Ruff 검사에는 이관 전부터 EXE001 두 건이 존재한다:
- examples/minimal_evaluate_example.py
- scripts/baseline_smoke.py

## 미완료 및 연결 필요 사항

- Evidence는 현재 테스트 대역이며 실제 SQLite 저장·조회는 미검증
- Wana의 수신 구현과 RunStatusUpdate 정의 위치 확인 필요
- 지송 Thin API의 Runtime 호출 및 객체 주입 연결 필요
- No Tool의 Context 검사는 최종 생성 응답 검사 완료를 의미하지 않음
- 실제 최종 응답 생성·검사 경로는 추가 연결 필요
- 실제 Runtime/Security/Evidence 통합 Smoke 필요
- Tool timeout/취소와 프로세스 재시작을 넘는 중복 실행 방지는 미구현

## Contract 및 PR

기존 shared Enum/Schema/Protocol 파일은 변경하지 않았다.

RuntimeRequest, RuntimeRunResult, RunStatusUpdate 등 Runtime 내부
DTO와 진입점은 연결 담당자 검토 및 Notion Interface Spec 갱신 대상이다.

PR은 feat/runtime-enforcement → dev로 제출한다.
공통 Contract 변경이 필요하면 관련 Producer/Consumer 확인 후 반영한다.
