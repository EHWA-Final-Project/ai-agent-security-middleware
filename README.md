# AI Agent Security Middleware

2026 이화여자대학교 졸업 프로젝트

다단계 연계형 Guard와 latency-aware enforcement를 적용한 AI Agent 보안 미들웨어입니다.

## Team

| Member | Ownership |
| --- | --- |
| Fatin | Security Core |
| Wana | Evidence / Evaluation |
| 이지원 | Runtime / Enforcement |
| 오지송 | Platform / Integration / Release QA |

## Current integration target

현재 Sprint의 최소 통합 경로:

```text
Runtime
  → Security Orchestrator
  → Enforcement
  → Evidence
```

Integration gate:

- 동일 `run_id` / `trace_id` 전파
- BENIGN 경로 정상 완료
- ATTACK 경로 BLOCK
- BLOCK된 Tool 실제 실행 횟수 0
- Guard timeout / error fallback 확인
- Evidence 저장 및 조회 확인

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
- Thin FastAPI boundary

> 공통 `pyproject.toml` / `uv.lock` / shared models는 Fatin의 현재 baseline 이관 후 팀 기준으로 확정합니다.

## Repository bootstrap

현재 공용 레포에는 팀 코드 이관 전에 필요한 중립적인 운영 설정만 먼저 구성되어 있습니다.

- `.python-version`
- `.gitignore`
- `.env.example`
- `.editorconfig`
- PR template
- team development workflow

팀 개발/이관 규칙은 [docs/TEAM_WORKFLOW.md](docs/TEAM_WORKFLOW.md)를 참고하세요.

## Integration order

1. Fatin — Repository Skeleton / Common Contract / Security Core baseline
2. Wana — Evidence / Evaluation 이관
3. 이지원 — Runtime / Enforcement 이관
4. 실제 Producer ↔ Consumer Interface 연결
5. 오지송 — Thin API / CI / Contract / Integration Smoke / Release QA

## Project documents

- Notion: https://app.notion.com/p/2026-AI-Agent-Security-Middleware-3ea800434d5380fd937efe9869397138
- Miro: https://miro.com/app/board/uXjVHm8WbuU=/

## CI

공통 `pyproject.toml`과 `uv.lock`이 `dev`에 반영된 뒤 아래 기준으로 CI를 활성화합니다.

```bash
uv sync --frozen
uv run ruff check .
uv run pytest -q
```

실제 Runtime / Security / Evidence 연동 후 Cross-layer integration smoke를 추가합니다.
