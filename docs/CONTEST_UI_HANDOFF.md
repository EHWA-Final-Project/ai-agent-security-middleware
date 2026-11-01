# Workbench 인계 · 2026-11-01

## 감사와 구현 상태
- 시작 dev / origin/dev: `75889b33a618762a8e490f8d1c44cdb639b34938`. fetch 후 동일. 작업 브랜치 `feat/contest-workbench-jisong`.
- 기존 완료: 정상·실행 전 차단·출력 차단 세 카드, 실제 SQLite 조회, 식별자 검증, 저장 이벤트 순서 Replay, 0.80/0.92 A/B/C Report와 B/C 집계 비교.
- 이번 개선: 결과 우선 동선, run/trace 상시 표시, 실행 전/후 차단 및 WARN 설명, Guard reason 표시, 9개 Attack ID 안내, Benchmark Lab의 계약 대기 빈 상태, 포스터 원고.
- 원격 공개 브랜치에 contest-security-core는 감사 시 발견되지 않았다. 열린 PR은 #14 FastAPI뿐이며 UI 수정 충돌은 발견되지 않았다. 미추적 `ai-agent-security-middleware/` 폴더는 기존 사용자 데이터로 보존한다.
- 새 UI는 demo/workbench.py에 분리했다. Core·Runtime·service·Evidence·평가 산식 및 공통 DTO는 변경하지 않는다.
- 팀 Notion 7·8·10·14절 참조. 계획의 완료 표시를 코드 구현 증거로 취급하지 않는다.

## B/C와 Benchmark 제한
기존 A/B/C Evaluation에서 동일 report 안의 B/C 집계를 조회한다. 개별 요청의 판정·Tool 실행·출력 전달은 집계에서 역추론하지 않는다. 개별 B/C 실행·Replay API가 없어 새 실행 버튼을 만들지 않았다. run/trace를 결합하거나 가공하지 않는다.

Benchmark Lab은 읽기 전용 준비 화면이다. 현재 공개 Benchmark 결과를 읽어 보여주는 기능은 계약·자료 인계 대기이며 완료로 주장하지 않는다. 기존 reports.py의 summary.json 계약 및 0.80/0.92 동작은 유지한다. 미제공 지표는 0으로 채우지 않는다.

## 담당자별 요청 (메시지 발송 아님)
| 담당 | 파일/함수 또는 산출물 | 필요한 정보 |
| --- | --- | --- |
| Fatin | SecurityResult / Agent adapter | Attack ID 매핑, 실제 모델/버전, 성공 기준, reason·latency·risk 필드, 대표 E2E run/trace. PI-T01 후속 호출 경계 검증 여부 |
| Wana | Benchmark exporter CSV/JSON | 확정 경로·완료 상태·버전·dataset 출처/버전·family·조건·Threshold·고유 n·trial·지표 분모·실패 처리·mean/p50/p95·차단 시점·Jailbreak 별도 결과. 실제 제공 시에만 P/R/F1 표시 |
| 이지원 | demo/service.py run_scenario / query_events | 동일 요청 B/C 실행 인터페이스 및 요청 동등성 식별자, 각 run/trace와 condition 보존, 실행 횟수·출력 전달·저장 Evidence 반환. 과거 condition 증거와 공개 세션 격리 방식 검토 |
| 오지송 | demo/workbench.py / reports.py / 포스터 | 확정 exporter용 읽기 어댑터, 요청별 B/C trace 비교 연결, 실측 그래프·캡션·실제 화면 교체 |

## 로컬 3분 시연 및 백업
`uv sync --frozen --group demo` 후 `uv run --group demo streamlit run demo/dashboard.py`.
1. 정상 카드 실행 → ALLOW, Tool 1회, 출력 전달 확인.
2. 공격 카드 실행 → BLOCK, Tool 0회 확인. 출력 차단 카드 → Tool 1회와 출력 차단 차이 확인.
3. Replay 한 단계 보기 → Guard 근거 → Evidence와 식별자 확인.
4. A/B/C Evaluation의 검증된 저장 Report 조회. 파일 없으면 빈 상태를 그대로 시연.

공개 배포는 수행하지 않았다. 현재 공유 DB/로컬 경로 입력 UI는 공개 세션 격리 검증 전 외부 서비스로 배포하지 않는다. 백업은 리허설 PC에 동일 환경과 검증된 report 배치, 합성 데이터 실행 화면 녹화이며 녹화 완료를 주장하지 않는다. 실제 secret/개인정보를 로컬 DB에 넣지 않는다.

## 완료 판단
10/31~11/1 범위에서 독립 수행 가능한 UI 정리·분류·빈 상태·포스터 초안은 구현했다. 실제 공개 Benchmark 표시, 개별 요청 B/C trace 비교, 실제 Agent 및 공개 배포는 인계·후속 검증 대기다. 전체 스프린트 완료로 표시하지 않는다.

## 검증 기록
- `uv sync --frozen --group demo`: 통과.
- `uv run --group demo pytest -q`: 최종 263개 대상. 기존 261개에 빈 Benchmark/공격 분류의 무실행 검증과 WARN 표시 검증을 추가했다. 결과는 PR 기록 참조.
- `uv run --group demo ruff check .`: 기존 미추적 중첩 폴더의 `tests/e2e/test_platform_api.py` I001로 실패. 해당 사용자 파일은 수정하지 않았다.
- `uv run --group demo ruff check demo tests src shared scripts`: 프로젝트 코드 통과.
- `git diff --check`: 통과.
- `uv run --group demo streamlit run demo/dashboard.py --server.headless true --server.port 8511`: 기동 후 `/_stcore/health` 응답 `ok`, 검증 후 종료. 화면 상호작용은 Streamlit AppTest로 검증했으며 수동 브라우저 시각 검수는 미수행.
