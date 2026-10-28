# Integration Checklist

10/29 발표 기준: 최신 `dev`, freeze candidate `6f2de1f3385d66d68ae9fa64047cd91c6b09a3e3`. 최신 검증은 **261 tests passed / Ruff pass / git diff --check pass**입니다. Dashboard는 Plugin-based AI Agent Security Middleware의 Presentation / Observability layer입니다.

## Repository baseline

- [x] Private team repository created
- [x] `main` stable branch
- [x] `dev` integration branch
- [x] Python 3.12 pin
- [x] .gitignore
- [x] .env.example
- [x] .editorconfig
- [x] Pull Request template
- [x] Team workflow
- [x] Fatin common baseline / Security Core merged (PR #18 포함)
- [x] `pyproject.toml` / `uv.lock` frozen 환경 검증 (`uv sync --frozen --group demo`)
- [ ] dev 자동 CI gate 활성화 및 통과 확인

Frozen 설치는 기존 검증 환경의 clean working tree에서 확인했습니다. 새 clone의 cold-start 검증을 이번 문서 작업에서 추가 수행한 것은 아닙니다. GitHub workflow registry의 `CI`는 active이나 현재 dev에는 workflow 파일과 dev run 이력이 없어 자동 CI gate 완료로 표시하지 않습니다.

## Producer → Consumer integration

### Fatin → 이지원
- [x] RuntimeObservation actual import
- [x] Orchestrator entry point (`SecurityOrchestrator.evaluate`)
- [x] SecurityDecision actual object
- [x] WARN / BLOCK / timeout contract verified

근거: `tests/contract/test_runtime_connected.py`, `test_orchestrator_contract.py`, `test_orchestrator_warn_policy.py`.

### Fatin → Wana
- [x] SecurityResult actual object
- [x] SecurityDecision actual object
- [x] Evidence fields compatible
- [x] Error / timeout evidence compatible

근거: `tests/contract/test_evidence_sink_contract.py`, `test_orchestrator_contract.py`, `tests/integration/test_runtime_experiment_adapter.py`. Guard failure의 null decision/risk와 error/latency 기록을 유지하며, 실패한 trial을 정상 Metrics에 포함하지 않습니다.

### 이지원 → Wana
- [x] RuntimeObservation evidence path
- [x] ExecutionResult actual object
- [x] RunStatus semantics (`COMPLETED` / `PARTIAL_FAILURE` / `FAILED`)
- [x] Tool failure semantics (실행 결과 보존, 출력 차단, 자동 재실행 없음)

근거: `tests/integration/test_runtime_evidence_sqlite.py`, `tests/contract/test_runtime_connected.py`.

### Wana → 오지송
- [x] Evidence query interface (`EvidenceQueryService`)
- [x] Run / Trace result shape (`RunResultDTO` / `TraceResultDTO`: 식별자 + events)
- [x] Metrics DTO / report access (`MetricsAggregator`, `summary.json` / CSV / PNG)
- [x] partial failure behavior (Evidence 실패 시 Tool 재실행 없이 `PARTIAL_FAILURE`, 실패 trial 집계 거부)

근거: `tests/unit/test_evidence_query_service.py`, `test_metrics_aggregator.py`, `test_runtime_evaluation_report.py`, `tests/integration/test_runtime_experiment_adapter.py`, `test_plugin_dashboard.py`.

### 이지원 → 오지송
- [x] Runtime service entry point (`RuntimeAdapter.run`, `demo.service.run_scenario`)
- [ ] POST /runs call boundary — Deferred: PR #14 FastAPI boundary is not part of the 10/29 presentation baseline.
- [x] Runtime result / error mapping (`RuntimeRunResult`; HTTP mapping은 deferred)

근거: `tests/contract/test_runtime_connected.py`, `tests/integration/test_plugin_dashboard.py`. PR #14의 stale baseline / 0.99 정책 / placeholder metrics / API 의존성은 [감사 기록](PLATFORM_API_AUDIT.md)을 참고합니다. PR #14는 미병합 상태로 유지하며, 현재 발표는 Streamlit service 직접 호출입니다.

## Cross-layer smoke

- [x] Frozen dependency verification (`uv sync --frozen --group demo`; 새 clone 재검증과 구분)
- [x] Ruff pass
- [x] Unit / Contract / Integration tests pass (261 tests, Dashboard AppTest 7개 포함)
- [x] Runtime → Security → Enforcement → Evidence connected
- [x] run_id / trace_id propagated end-to-end
- [x] BENIGN path ALLOW / EXECUTED / Tool 1 / Output 전달
- [x] Guard 적용 ATTACK path BLOCK / Tool execution count 0
- [x] Output-block path: Tool 1 / 사용자 출력 차단
- [x] ERROR-001 Tool Guard TIMEOUT fail-closed BLOCK / BLOCKED / Tool 0 / Runtime E2E verified
- [x] Evidence stored and queryable (실제 SQLite)
- [x] A/B/C → Runtime → Evidence → Evaluation / Metrics 연결
- [x] 360 Trial result verified (팀 최종 QA 확인; 0.80 / 0.92 각 180회, 산출물 별도 배치)
- [x] Dashboard / Evidence Replay verified (저장 순서 보존, 추가 Runtime 호출 없음)
- [x] Demo command documented ([발표 가이드](PRESENTATION_DEMO.md))

Runtime E2E timeout 회귀 근거: `tests/contract/test_runtime_connected.py::test_tool_guard_timeout_blocks_real_enforcement`. ERROR-001은 Tool 실행 자체의 취소가 아니라 **Tool Guard 검사 timeout** 경로입니다. A는 Guard가 없어 공격 Tool 실행을 허용할 수 있으며, 위 ATTACK 차단 체크는 Guard 적용 경로를 뜻합니다.

## Presentation freeze 판단과 남은 범위

Runtime / Enforcement 추가 blocker 없이 presentation freeze candidate입니다. 360 Trial은 전달된 팀 최종 QA의 확인 결과이며 이번 문서 작업에서 새 공식 실험이나 보고서 수치를 생성하지 않습니다. 0.92는 mechanism demonstration이며 성능 우위를 일반화하지 않습니다.

발표 PC에는 검증된 report를 `reports/`에 별도 배치하고 실제 화면 / 자동 Replay 리허설을 확인해야 합니다. 자동 CI, PR #14 API 통합, Tool 실행 자체의 timeout / 취소, 프로세스 재시작을 넘는 exactly-once 보장은 완료 범위가 아닙니다. `main` release merge는 발표 후 별도 판단합니다.
