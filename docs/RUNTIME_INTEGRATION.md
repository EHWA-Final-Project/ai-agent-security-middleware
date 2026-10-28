# Runtime / Enforcement 통합 현황

작성자: 지원

10/29 발표 기준 갱신: `dev`, freeze candidate `6f2de1f3385d66d68ae9fa64047cd91c6b09a3e3`. Runtime / Enforcement 추가 blocker 없이 presentation freeze 가능한 통합 상태다.

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
- PluginManager 기반 네 Guard 및 SecurityContext 기반 Independent / Linked coordination 연결
- 실제 SQLite Evidence 저장·run / trace 조회, A/B/C → Runtime → Evidence → Evaluation / Metrics 연결

Dashboard는 이 실행과 저장 Evidence를 보여주는 Presentation / Observability layer다. FastAPI thin boundary from PR #14 is deferred and excluded from the 10/29 presentation baseline.

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

    uv sync --frozen --group demo
    uv run --group demo pytest -q
    uv run --group demo ruff check .
    git diff --check

최신 전체 검증 기준 **261 passed / Ruff All checks passed / git diff --check pass**다.

- 실제 SQLite 저장·조회 및 `run_id` / `trace_id` 연결: `tests/integration/test_runtime_evidence_sqlite.py`
- Runtime / Security / Enforcement 연결, WARN 출력 보류, BLOCK Tool 0회, Evidence 장애 및 Tool 실패 의미: `tests/contract/test_runtime_connected.py`
- A/B/C Runtime → SQLite Evidence: `tests/integration/test_conditions_runtime_evidence.py`
- Runtime → Evidence → Evaluation 및 실패 trial 거부: `tests/integration/test_runtime_experiment_adapter.py`
- Dashboard 세 시나리오 / Evidence Replay / 과거 run 조회: `tests/integration/test_plugin_dashboard.py`

세 Runtime 시나리오 회귀 검증 결과:

| 경로 | 실제 결과 |
|---|---|
| 정상 요청 | ALLOW / Tool 1회 / Output 전달 |
| 실행 전 공격 | BLOCK / Tool 0회 / Output 차단 |
| 실행 후 출력 차단 | Tool 1회 / Output 차단; 실행 결과 보존 |

ERROR-001 Tool Guard timeout 경로는 fail-closed BLOCK, `execution_state=BLOCKED`, Tool call count 0으로 Runtime E2E 검증 완료다. 회귀 근거는 `test_runtime_connected.py::test_tool_guard_timeout_blocks_real_enforcement`이며, 실제 RuntimeAdapter / Orchestrator / Enforcement에 제어된 Guard 지연을 주입해 확인한다. timeout error / latency Evidence 계약은 `test_orchestrator_contract.py`에서도 검증한다. 이는 Tool 함수 실행 자체의 timeout / 취소 구현을 뜻하지 않는다.

Wana Evidence 수신 연결은 완료됐으며 `RunStatusUpdate`는 `src/runtime/ports.py`에 정의되어 있다. Evidence 수신은 `EvidenceCollector` / `SQLiteEvidenceRepository`, Query는 `EvidenceQueryService`로 연결한다. Evidence 장애 시 `PARTIAL_FAILURE`, Tool 실행 실패 시 `FAILED`를 보고하고 자동 재실행하지 않는다.

A/B/C Evaluation의 ASR / TSR / FPR / Block Rate 및 mean / p50 / p95 latency 집계가 연결되어 있다. 팀 최종 QA에서 총 360 Trial 결과를 확인했다 (0.80 baseline / 0.92 mechanism demonstration 각 180회). 보고서는 Git 밖에서 관리하고 발표 PC에 별도 배치한다. 0.92는 일반적인 성능 우위의 근거가 아니며 고정 정상·공격 각 1종의 반복 검증 범위다.

## Known limitations / 후속 범위

- PR #14 Thin API의 HTTP boundary 연결은 deferred이며 발표 Runtime 실행에 필요하지 않음
- No Tool의 Context 검사는 최종 생성 응답 검사 완료를 의미하지 않음
- 실제 LLM 최종 응답 생성·검사는 현재 Mock Tool 출력 검사와 별도 후속 연결 범위
- Tool 실행 자체의 timeout / 취소 및 프로세스 재시작을 넘는 exactly-once / 중복 실행 방지 보장은 미구현
- inspection_mode / STANDARD → STRICT 전환은 SQLite Evidence에 저장되지 않으므로 실행 결과처럼 표시하거나 추론하지 않음

## Contract 및 PR

기존 shared Enum/Schema/Protocol 파일은 변경하지 않았다.

RuntimeRequest, RuntimeRunResult, RunStatusUpdate와 RuntimeAdapter / demo service 진입점은 현재 통합 경로에서 사용한다. 외부 Notion Spec 갱신 완료 여부는 이 문서의 코드·테스트 검증과 구분한다.

발표 실행 기준은 기존 feature branch가 아닌 검증된 `dev`다. 이후 공통 Contract 변경이 필요하면 관련 Producer/Consumer 확인 후 별도 반영한다. `main` release merge는 발표 후 별도 판단한다.
