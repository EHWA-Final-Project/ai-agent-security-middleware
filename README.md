# AI Agent Security Middleware

2026 이화여자대학교 졸업 프로젝트

PluginManager 기반 Guard Plugin과 SecurityContext 기반 Cross-layer Coordination을 적용한 AI Agent 보안 미들웨어입니다.

## Team

| Member | Ownership |
| --- | --- |
| Fatin | Security Core |
| Wana | Evidence / Evaluation |
| 이지원 | Runtime / Enforcement |
| 오지송 | Platform / Integration / Release QA |

## Current integration target

10/29 발표 기준 통합 경로 (`dev`, freeze candidate `6f2de1f3385d66d68ae9fa64047cd91c6b09a3e3`):

```text
Runtime
  → Security Orchestrator
  → Plugin Manager
  → Input / Context / Tool / Output Guard Plugins
  → SecurityContext / Cross-layer Coordination
  → SecurityDecision
  → Enforcement
  → SQLite Evidence
  → Evaluation / Metrics
  → Presentation Dashboard
```

위 구조는 구성 요소의 연결 관계입니다. Tool 실행 후 OUTPUT 검사로 사용자 출력 전달을 차단할 수 있으며, 실제 이벤트 순서는 저장 Evidence를 따릅니다. Dashboard는 별도 보안 로직이 없는 Presentation / Observability layer입니다.

완료된 Integration gate:

- [x] 동일 `run_id` / `trace_id` end-to-end 전파
- [x] BENIGN ALLOW / EXECUTED / Tool 1회 / Output 전달
- [x] Guard 적용 ATTACK BLOCK / Tool 실행 0회 / Output 차단
- [x] Output-block 경로: Tool 1회 실행 후 사용자 출력 차단
- [x] ERROR-001 Tool Guard timeout → fail-closed BLOCK / BLOCKED / Tool 0회, Runtime E2E 검증
- [x] SQLite Evidence 저장 및 run / trace 조회
- [x] A/B/C → Runtime → Evidence → Evaluation / Metrics 연결
- [x] 총 360 Trial 결과 확인 (팀 최종 QA 확인; 검증된 report는 발표 PC에 별도 배치)
- [x] Streamlit Dashboard / 저장 Evidence Replay 검증

A = No Guard, B = Independent, C = Linked / Cross-layer입니다. 0.80은 baseline, 0.92는 mechanism demonstration이며 일반적인 성능 우위를 증명하지 않습니다. 실험은 Mock Tool과 BENIGN-001 / ATTACK-001 각 1종의 반복 실행으로, 전체 공격 환경의 최종 보안 성능으로 일반화하지 않습니다.

### Guard 적용 범위

- Input·Context·Tool Guard는 모델 호출 이후, 실제 Tool 실행 이전에 동작한다. Output Guard는 Tool 실행 이후, 사용자에게 전달하기 전에 동작한다.
- Tool 호출이 없는 모델 응답과 `reply.text`는 검사하지 않는다. 검사 대상은 Tool 호출을 요청한 턴이다.
- 정상 `send_email`은 기본 설정에서 WARN이며, 이 경우 Tool은 실행되고 결과 전달만 보류된다. `ToolPolicy`로 허용 범위를 지정하면 범위 안의 호출은 ALLOW가 된다.

## Branch strategy

- `main` — stable / release
- `dev` — team integration
- `feat/*`, `chore/*` — individual work

직접 `main` / `dev`에서 개발하지 않고 개인 branch에서 작업 후 `dev` PR을 사용합니다.

Recommended branches:

- Fatin — `feat/security-core`
- Wana — `feat/evidence-evaluation`
- 이지원 — `feat/runtime-enforcement`
- 오지송 — `chore/platform-integration`

## Environment baseline

- Python 3.12
- uv
- pytest
- Ruff
- Streamlit Dashboard (`demo` dependency group)
- SQLite Evidence / Mock Tools

공통 baseline과 `pyproject.toml` / `uv.lock`은 `dev`에 통합되었으며 frozen 설치를 검증했습니다.

공식 발표 실행은 `pyproject.toml`, `uv.lock`, `demo/`가 있는 최신 `dev` repository root에서 진행합니다.

```bash
git rev-parse --show-toplevel
git branch --show-current
git rev-parse HEAD
uv sync --frozen --group demo
uv run --group demo pytest -q
uv run --group demo ruff check .
uv run --group demo streamlit run demo/dashboard.py
```

FastAPI thin boundary from PR #14 is deferred and excluded from the 10/29 presentation baseline. FastAPI / uvicorn / httpx API 의존성은 현재 공식 발표 dependency에 추가하지 않습니다. 실행·report 배치는 [Presentation guide](docs/PRESENTATION_DEMO.md)를 참고하세요.

## Repository bootstrap

공용 레포에는 통합 코드와 다음 운영 설정이 반영되어 있습니다.

- `.python-version`
- `.gitignore`
- `.env.example`
- `.editorconfig`
- PR template
- team development workflow

팀 개발/이관 규칙은 [docs/TEAM_WORKFLOW.md](docs/TEAM_WORKFLOW.md)를 참고하세요.

## Integration order

Common Contract / Security Core → Runtime / Enforcement → SQLite Evidence → Evaluation / Metrics 연결과 발표 Dashboard / Replay 통합을 완료했습니다. Thin API와 dev 자동 CI gate는 별도 후속 작업입니다.

## Current validation

- Freeze candidate `dev` HEAD: `6f2de1f3385d66d68ae9fa64047cd91c6b09a3e3` (PR #20–#23 merge 완료)
- 최신 검증: **261 tests passed**, Ruff pass, `git diff --check` pass
- Runtime / Evidence / Evaluation integration 및 세 Runtime 시나리오 회귀 검증 완료
- Runtime / Enforcement 추가 blocker 없음; presentation freeze candidate

검증 범위와 미완료 항목은 [Integration checklist](docs/INTEGRATION_CHECKLIST.md)에 구분합니다. 발표 PC의 검증된 report 배치와 리허설은 별도로 확인합니다. `main` release merge는 발표 후 별도 판단합니다.

## Project documents

- Notion: https://app.notion.com/p/2026-AI-Agent-Security-Middleware-3ea800434d5380fd937efe9869397138
- Miro: https://miro.com/app/board/uXjVHm8WbuU=/

## CI

현재 `dev` 기준에는 GitHub Actions workflow 파일이 없고 dev 실행 기록도 확인되지 않았습니다. GitHub workflow registry에는 `CI`가 active로 남아 있으나, 이를 발표 baseline의 자동 CI 검증 완료로 취급하지 않습니다. 현재 검증 근거는 로컬 frozen 환경의 다음 명령입니다.

```bash
uv sync --frozen --group demo
uv run --group demo ruff check .
uv run --group demo pytest -q
```

Runtime / Security / Evidence Cross-layer smoke와 Dashboard AppTest는 기존 테스트에 포함되어 있습니다. dev 자동 CI gate 구성은 후속 작업입니다.


## Team onboarding

- [Team workflow](docs/TEAM_WORKFLOW.md)
- [Local work migration guide](docs/MIGRATION_GUIDE.md)
- [Integration checklist](docs/INTEGRATION_CHECKLIST.md)
