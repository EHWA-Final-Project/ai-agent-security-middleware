# Runtime Security Demo

준비된 시나리오를 실제 Runtime → Security Core → Enforcement → SQLite Evidence 흐름으로 실행하고, Streamlit에서 결과를 조회합니다.

- 입력과 Tool 후보는 미리 정의된 시나리오입니다.
- Tool은 Mock 구현이며 실제 파일 읽기나 이메일 발송을 하지 않습니다.
- Guard 판정은 SQLite에 저장된 실제 Evidence에서 가져옵니다.
- Runtime을 직접 호출하며, Thin API를 통한 실행은 포함하지 않습니다.

## 준비

Git, uv, 저장소 접근 권한이 필요합니다.
아래 실행 명령은 macOS와 Windows PowerShell에서 사용할 수 있습니다.
현재 실행 검증은 macOS에서 완료했으며 Windows는 팀원 확인이 필요합니다.

저장소를 새로 받는 경우:

```sh
git clone --branch feat/sprint2-demo https://github.com/EHWA-Final-Project/ai-agent-security-middleware.git
cd ai-agent-security-middleware
```

이미 저장소가 있다면 작업 내용을 먼저 커밋하거나 보관한 뒤:

```sh
git fetch origin
git switch feat/sprint2-demo
git pull --ff-only origin feat/sprint2-demo
```

저장소 최상위 폴더에서 의존성을 설치합니다.

```sh
uv sync --frozen --group demo
```

## 실행

터미널 1에서 시나리오를 실행합니다.

```sh
uv run --group demo python demo/cli.py
```

1, 2, 3 중 하나를 입력합니다. q를 입력하면 종료됩니다.

터미널 2를 열고 같은 저장소 폴더에서 대시보드를 실행합니다.

```sh
uv run --group demo streamlit run demo/dashboard.py --server.address 127.0.0.1 --browser.gatherUsageStats false
```

브라우저에서 http://127.0.0.1:8501 에 접속합니다.
CLI 실행 후 대시보드의 '목록 새로고침'을 누르고 같은 run_id를 선택합니다.
대시보드는 저장된 결과를 조회하며 시나리오를 재실행하지 않습니다.
서버는 Ctrl+C로 종료합니다.

## 예상 결과

| 시나리오 | Guard 결과 | 최종 판정 | Tool 호출 | 출력 전달 |
| --- | --- | --- | --- | --- |
| 1. 정상 문서 읽기 | 4단계 ALLOW | ALLOW | 1회 | 허용 |
| 2. 실행 전 공격 차단 | INPUT WARN, risk 0.9 | BLOCK | 0회 | 차단 |
| 3. 실행 후 출력 차단 | OUTPUT WARN, risk 0.95 | BLOCK | 1회 | 차단 |

Guard 개별 판정과 최종 정책 판정은 다를 수 있습니다.
COMPLETED는 요청 처리가 완료되었다는 의미이며 허용 여부는 최종 판정으로 확인합니다.
검사 기록이 없는 단계는 ALLOW로 간주하지 않습니다.

## 실행 데이터

SQLite Evidence와 실행 요약 JSON은 demo/.data/에 저장됩니다.
각 컴퓨터에서 별도로 생성되며 Git에는 포함되지 않습니다.
프로그램을 종료해도 기록은 유지됩니다.

## 검증

```sh
uv run --group demo pytest -q
uv run --group demo ruff check .
```

공유 준비 시 기존 테스트 115개와 Ruff 검사를 통과했습니다.
세 데모 시나리오는 CLI와 대시보드에서 수동 확인했습니다.
