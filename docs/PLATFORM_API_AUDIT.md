# Platform API PR #14 감사

비교 기준: dev `14c9ffec18dc4d9573354ebd11c47c944fb4ebdc`, 원격 `origin/feat/platform-demo`. 공통 조상은 `067bafd87b7bd39f19b844e1cada2981765035c5`이다. merge / cherry-pick은 수행하지 않았다.

| 파일 / 영역 | 가치와 현재 판단 |
|---|---|
| `src/platform_api/app.py` | `/health`, `/runs`, run / trace Evidence 조회 경계는 후속 Platform API 설계에 유용하다. `/metrics`는 P0_PLACEHOLDER이며 현재 MetricsAggregator와 연결되지 않았다. |
| `src/platform_api/container.py` | Runtime / Evidence 조립 예시는 유용하나 공유 Mock Tool 인스턴스, 별도 정책과 lifecycle / 동시성 검토가 필요하다. `strict_threshold=0.50`, `block_threshold=0.99`를 쓰므로 발표용 0.80 / 0.92 정책과 호환되는 결과로 취급하면 안 된다. |
| `src/platform_api/demo.py` | 대형 HTML 데모. 현재 CLI / Streamlit / service 시나리오 실행과 Evidence 조회가 발표 기능을 충족한다. 두 UI를 운영할 필요가 없다. |
| `scripts/run_platform_demo.py`, `.sh` | 후속 API 서버 실행 예시. 현재 발표 실행 경로에는 불필요하다. |
| `tests/e2e/test_platform_api.py` | 추후 API 계약 회귀 테스트에 참고할 수 있다. 최신 schema / policy / metrics 기준으로 재검증해야 한다. |
| `.github/workflows/ci.yml` | frozen sync 뒤 FastAPI / uvicorn / httpx를 별도 `uv pip install`하는 임시 overlay다. 발표 브랜치 CI를 그대로 대체하지 않는다. |
| `docs/DEMO_GUIDE.md`, `docs/INTEGRATION_CHECKLIST.md` | 구 API 경로·의존성·정책을 전제하므로 현재 발표 문서로 대체해서는 안 된다. |

## 최신 dev와 차이 / 충돌 위험

두 tip을 비교하면 Platform 브랜치에는 최신 `experiment_runner`, `metrics_aggregator`, `runtime_trial_adapter`, A/B/C condition YAML / loader, security measurement가 없다. Security orchestrator / policy config와 uv.lock도 다르다. 이는 두 tip의 차이이며 merge 시 해당 파일이 반드시 삭제된다는 뜻은 아니다. 과거 branch 전체를 현재 통합 상태로 취급할 수 없다는 근거다.

실행 조립과 Mock Tool / SQLite 조회는 이미 `demo/service.py`가 제공한다. 최신 dev에는 실제 Runtime → Evidence → Evaluation → Metrics 연결이 있으므로 placeholder metrics를 가져오면 설명과 결과가 후퇴한다.

## 의존성 영향

PR의 API는 FastAPI, 서버는 uvicorn, TestClient 계열 테스트는 httpx가 필요하다. PR CI의 overlay 범위는 각각 `fastapi>=0.118,<1`, `uvicorn>=0.37,<1`, `httpx>=0.28,<1`이며 pyproject / lock 기반 frozen 설치에 정식으로 반영되어 있지 않다. 새 API 패키지와 Starlette 등 전이 의존성, CI 동작 변경은 freeze 직전 추가 검증 부담이 된다. 이번 작업은 pyproject / uv.lock을 변경하지 않는다.

## 발표 반영 판단

Dashboard와 QA 완료 후에도 이번 발표에 반드시 필요한 API 요소는 없다. 현재 service 재사용으로 목표를 충족하며, 아주 작은 health endpoint조차 새 서버·의존성과 운영 경로를 추가한다. 따라서 PR #14 파일을 가져오지 않는다. 후속 작업에서 최신 dev 기반으로 API 경계만 재작성하고 A/B/C 정책 식별, 실제 metrics, 요청별 lifecycle 및 API 테스트를 통합한다.
