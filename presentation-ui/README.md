# GuardOn Presentation UI

React + TypeScript + Vite로 구현한 읽기 전용 보안 분석 플랫폼. 기존 Streamlit과 Python 보안·평가 코드는 보존한다. Node.js 22.12 이상이 필요하다(검증 환경: Node 24.13.0).

## 실행

```powershell
cd presentation-ui
npm.cmd ci
npm.cmd run build
npm.cmd run preview
```

http://127.0.0.1:5173 . `Recorded / Replay` 모드이며 LLM·MCP·SQLite를 실시간 호출하지 않는다.

```powershell
npm run data
npm run verify-data
npm run typecheck
npm test
npm run build
npm run preview
```

`data`/`verify-data`는 uv 및 기존 Python의 검증 로더를 사용한다. 공개 JSON/CSV만 소비하며 보안 정책·평가 계산·원본 기록을 변경하지 않는다. 그래프는 원본 PNG를 그대로 사용한다.

일반 실행에는 Python이나 API 키가 필요하지 않다. 공개 데이터가 이미 포함되어 있다. 개발 중에는 `npm.cmd run dev`를 사용한다. 5173이 이미 사용 중이면 기존 서버를 확인하거나 `npm.cmd run preview -- --port 5174`로 다른 포트를 선택한다.

## 실제 브라우저 QA

저장소 루트에서 `uv sync --locked --group dev --group demo` 후 이 디렉터리에서 실행한다. 기본적으로 로컬 Chrome이 필요하며, 별도 개인 프로필을 사용하지 않는다. Preview 서버는 별도 터미널에서 켜 둔다.

```powershell
uv run --project .. --with playwright python -X utf8 scripts/browser_qa.py
```

5개 화면을 1920×1080과 1366×768에서 캡처하고 검색·필터·URL 복원·Candidate 선택·상세 패널·복사·Escape/focus 복귀·원본 그래프와 CSV·모바일 탐색·데이터 로딩 실패를 검증한다. 결과는 `docs/assets/react-dashboard/after/browser-qa.json`과 PNG에 기록한다.

Benchmark 48시도와 Runtime 29건은 별도 집계다. 공식 ASR/TSR/FPR은 N/A이며, 없는 필드는 unknown이다. UI가 새로운 실시간 모델/Tool 실행이나 인과적 방어 효과를 증명하지 않는다.
