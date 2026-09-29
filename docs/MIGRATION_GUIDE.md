# Local Work Migration Guide

이 문서는 9/23~9/27 동안 각자 로컬에서 진행한 구현을 공용 Repository로 안전하게 이관하기 위한 기준입니다.

## 공통 원칙

- 기존 로컬 Git history를 공용 Repository에 그대로 merge하지 않습니다.
- 공용 Repository를 새로 clone한 뒤 최신 `dev`에서 자기 branch를 생성합니다.
- 기존 로컬 프로젝트에서 **필요한 구현 코드와 테스트만** 새 branch로 옮깁니다.
- 공통 Enum / Schema / ID / Protocol은 팀 기준을 우선합니다.
- 임시 Mock / Spy / duplicated common model은 실제 연결 시 제거하거나 교체합니다.
- `main`, `dev` 직접 push는 사용하지 않고 PR로 반영합니다.

## 1. Fatin · Security Core baseline

Fatin이 가장 먼저 이관합니다.

이유:
- Repository skeleton
- Common Enum / Schema
- Common ID
- shared contracts
- Plugin Core
- Security Orchestrator
- Policy config
- baseline smoke / tests

가 다른 파트의 공통 기준이기 때문입니다.

### 시작

```bash
git clone https://github.com/EHWA-Final-Project/ai-agent-security-middleware.git
cd ai-agent-security-middleware
git checkout dev
git pull origin dev
git checkout -b feat/security-core
```

### 이관 대상

- repository skeleton
- `pyproject.toml`
- `uv.lock`
- common Enum / Schema / ID
- shared contracts
- Plugin Core
- Security Orchestrator
- Policy config
- Input Guard baseline
- baseline smoke script
- Unit / Contract / Integration tests

### PR 전 확인

```bash
uv sync --frozen
uv run ruff check .
uv run pytest -q
```

가능하면 baseline smoke도 함께 실행합니다.

## 2. Wana · Evidence / Evaluation

Fatin baseline이 `dev`에 merge된 뒤 최신 `dev`에서 branch를 만듭니다.

```bash
git checkout dev
git pull origin dev
git checkout -b feat/evidence-evaluation
```

### 이관 대상

- BENIGN / ATTACK / ERROR Fixture
- SecurityEvent model
- Evidence Builder
- SQLite Evidence Store
- Evaluation package
- Unit / Contract tests

### 교체 / 정리

- 로컬 임시 Common Schema가 있으면 shared 기준으로 교체
- Mock SecurityResult / Decision은 실제 shared model import로 교체
- run_id / trace_id / scenario_id 규칙 확인

## 3. 이지원 · Runtime / Enforcement

Fatin baseline이 `dev`에 merge된 뒤 최신 `dev`에서 branch를 만듭니다.

```bash
git checkout dev
git pull origin dev
git checkout -b feat/runtime-enforcement
```

### 이관 대상

- Runtime Adapter
- RuntimeObservation
- ID 생성 / 전파
- read_file / send_email Mock Tool
- Enforcement
- ExecutionResult / RunStatus
- Unit / Contract / Smoke tests

### 교체 / 정리

- Security Mock → 실제 Orchestrator 호출로 교체 준비
- 임시 local models → shared models
- Evidence Spy → 실제 Evidence Store 연결 준비
- WARN 임시 처리와 실제 Decision 규약 차이 명시

## 4. 오지송 · Platform / Integration / QA

다른 파트의 실제 코드가 `dev`에 들어오기 전까지는 중립적인 Repository 운영환경과 QA 기준을 관리합니다.

실제 baseline 이관 후:

- Thin FastAPI
- `/health`
- `POST /runs`
- Run / Trace / Metrics query wiring
- CI
- Contract / Integration Smoke
- E2E / Release checklist

를 연결합니다.

## Pull Request

모든 PR은 `dev`를 base로 사용합니다.

PR Template에서 최소 다음 항목을 작성합니다.

- Related Task / Interface Spec
- Contract Impact
- 실제 실행한 Test command
- Integration Check
- Blocker

## Contract 변경

공통 Enum / Schema / DTO / Protocol / public function signature 변경 시:

1. Notion Interface Spec 수정
2. 연결 Producer / Consumer 확인
3. Contract Test 수정
4. PR에서 변경 영향 명시

## Sprint 2 Integration Gate

최종적으로 아래 경로가 실제 구현으로 연결되어야 합니다.

```text
Runtime → Security Orchestrator → Enforcement → Evidence
```

필수 확인:

- 동일 run_id / trace_id 전파
- BENIGN ALLOW
- ATTACK BLOCK
- BLOCK된 Tool 실제 실행 횟수 0
- Guard timeout / error fallback
- Evidence 저장 / 조회
- 최소 통합 Smoke 통과
