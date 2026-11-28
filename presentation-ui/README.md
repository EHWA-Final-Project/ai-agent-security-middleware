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

Windows에서 `npm.cmd ci`로 재설치하기 전에는 이 디렉터리에서 실행 중인 dev/preview 서버를 해당 터미널의 Ctrl+C로 종료한다. Vite가 사용 중인 네이티브 모듈은 Windows에서 삭제할 수 없어 `EPERM unlink`가 발생할 수 있다. 설치 실패 뒤 `tsc`/`vite`를 찾지 못하면 설치가 끝나지 않은 상태이므로, 서버를 종료하고 `npm.cmd ci`를 다시 성공시킨 뒤 빌드한다. 평소 재실행은 재설치 없이 `npm.cmd run preview`만 사용한다. Git Bash에서 설치부터 연속 실행하려면 실패 시 다음 단계가 실행되지 않도록 `npm.cmd ci && npm.cmd run build && npm.cmd run preview`로 연결한다.

## 실제 브라우저 QA

저장소 루트에서 `uv sync --locked --group dev --group demo` 후 이 디렉터리에서 실행한다. 기본적으로 로컬 Chrome이 필요하며, 별도 개인 프로필을 사용하지 않는다. Preview 서버는 별도 터미널에서 켜 둔다.

```powershell
uv run --project .. --with playwright python -X utf8 scripts/browser_qa.py
```

5개 화면을 1920×1080과 1366×768에서 캡처하고 검색·필터·URL 복원·Candidate 선택·상세 패널·복사·Escape/focus 복귀·원본 그래프와 CSV·모바일 탐색·데이터 로딩 실패를 검증한다. 결과는 `docs/assets/react-dashboard/after/browser-qa.json`과 PNG에 기록한다.

Benchmark 48시도와 Runtime 29건은 별도 집계다. 공식 ASR/TSR/FPR은 N/A이며, 없는 필드는 unknown이다. UI가 새로운 실시간 모델/Tool 실행이나 인과적 방어 효과를 증명하지 않는다.

## 팀원용 웹 링크 · GitHub Pages

설치 없이 볼 수 있는 공개 읽기 전용 사이트(배포 성공 후):
https://ehwa-final-project.github.io/ai-agent-security-middleware/

- 로컬 Node.js/Python/Ollama/API 키 없이 브라우저로 열람 가능
- 저장된 공개 실험 기록만 조회하는 Recorded/Replay 화면이며 Live MCP 호출을 하지 않음
- GitHub Pages는 `dev`에서 `.github/workflows/deploy-dashboard-pages.yml`을 실행하여 `presentation-ui/dist` 정적 파일을 게시
- 변경 시 워크플로의 `Build GitHub Pages site` 단계가 `GITHUB_PAGES=true`로 Vite 기본 경로를 `/ai-agent-security-middleware/`로 설정. 기존 localhost 실행은 `/` 유지
- 팀에게 URL을 전달하기 전 실제 Actions 배포 성공 여부 및 브라우저의 그래프·CSV·5개 화면 로딩 확인

### 최초 배포 설정 (저장소 관리자)

1. GitHub 저장소 **Settings → Pages** 열기
2. **Build and deployment → Source = GitHub Actions** 선택
3. **Actions → Deploy GuardOn Dashboard to GitHub Pages** 실행 (`Run workflow`, branch `dev`)
4. 배포 Job이 성공하면 위 URL을 열어 실제 데이터를 확인

저장소 관리자가 해당 설정을 활성화하지 않으면 워크플로만으로 공개 사이트가 준비됐다고 간주하지 않습니다. GitHub Pages는 공개 웹사이트이므로 공개 JSON에 실험 식별자·메타데이터가 포함되어 있음을 확인한 뒤 공유하세요.
