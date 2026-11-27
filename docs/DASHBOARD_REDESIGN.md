# Dashboard 리디자인: Academic Security Research Console

## 변경 전 진단과 구현 계획

기준: `guardon-freeze-20261127`, `4a569752a905666c1b52229edb52825b7a01b579`. Freeze tag는 변경하지 않는다. `ui/dashboard-redesign-20261127`에서 UI만 변경한다.

| 화면 | 기존 문제 | 재배치 계획 |
|---|---|---|
| Overview | 300px 사이드바, 작은 radio 메뉴, 터미널 구조도, 큰 JSON | 상단 탐색, 핵심 수치 strip, 4단계 구조도, 조건/검증 결과 2열, 설정 접기 |
| Actual Agent–MCP | 수십 열의 원본 표가 먼저 나옴 | 사람이 읽는 기록 선택, 모델 선택/판정/SDK·서버/전달 경계, 핵심 표, 원본 접기 |
| A/B/C/D Comparison | 반복 ID와 긴 필드명이 비교를 방해 | 동일 표본의 조건별 상태·실행·차단·전달 비교, Candidate 세부표, D 설명 |
| External Benchmark | 원본 metric row와 JSON, 거대한 그래프 수직 나열 | 출처/상태 요약, 분자·분모·scope 표, 공식 N/A 안내, 원본 그래프 5종 탭 |
| Evidence / Replay | ID와 원본 열이 핵심 상태보다 먼저 | Candidate 조사, 실행 경계, Guard 근거, 원본 식별자·기록 접기, Fixture 별도 유지 |

## 실제 적용한 스킬

모두 `$CODEX_HOME/skills`에 설치하며 프로젝트에 외부 스킬 파일은 커밋하지 않는다.

- **redesign-existing-projects**: 공식 taste-skill 보존 commit `73adb37611dbaf84d996d01131ab90f711947383`, `skills/redesign-skill/SKILL.md`. 기존 stack 감사 → 진단 → 기능 유지 리디자인, 글자 크기/숫자 정렬/선택 상태/empty·error 상태 적용. 최신 공식 저장소에서는 이 이름이 design-taste-frontend로 통합되었으므로 보존된 정확한 이름의 지침을 읽었다.
- **minimalist-ui**: 같은 공식 보존 commit, `skills/minimalist-skill/SKILL.md`. 평면 표면, 절제한 구분선, shadow/gradient/장식 제거, 촘촘한 타이포 위계 적용. 사용자의 밝은 cool-grey·navy·teal 콘솔 요구가 warm palette/거대한 여백/애니메이션 권고보다 우선한다.
- **UI/UX Pro Max**: 공식 repo `72e5fc76a4f3eb37747dc472cb3091bd46e7752a`, `.claude/skills/ui-ux-pro-max`. design-system 검색의 Analytics Dashboard / Minimalism & Swiss Style과 한국어 typography 검색의 Korean Modern을 참고했다. `--variance 3 --motion 1 --density 7`을 실제 지원하는 검색기에 전달했다. 반환된 Enterprise Gateway marketing layout은 재검색에서도 연구 콘솔에 부적합해 적용/저장하지 않았다. Streamlit stack 전용 검색은 지원하지 않아 임의로 React 결과를 적용하지 않았다. 한국어 system font fallback, 16px 본문, 대비 4.5:1, 표 안 스크롤, semantic status, focus 및 reduced-motion 적용.
- **web-design-guidelines**: vercel-labs/agent-skills `5a37a6329fbad3666c3207392a6a7c0110e92efb`, bundled `references/command.md`로 최종 검수. native 입력 label/keyboard, heading 계층, focus, 긴 ID 줄바꿈, 표 숫자, 이미지 alt, 조회 상태 URL 유지 점검.

참고 글: https://best-onedevyjuns.tistory.com/147 은 확인했다. https://it-ability.tistory.com/231 은 일반/모바일 주소 모두 열리지 않아 확인했다고 주장하지 않는다. 실제 지침은 위 공식 저장소 SKILL.md를 사용했다.

## 디자인 시스템

- Canvas `#F5F7FA`, surface `#FFFFFF`, text `#172B42`, secondary `#516176`, accent `#0B6B66`, divider `#DCE3EB`.
- 상태는 텍스트와 색을 함께 사용한다. Timeout(amber), 오류/BLOCK(red), 완료/ALLOW(teal), unknown(gray)은 별도 표현한다.
- 한국어: Noto Sans KR → Malgun Gothic → Apple SD Gothic Neo → system sans. 외부 폰트/CDN 연결을 필수로 만들지 않는다.
- 본문 16px, 보조 14px, 화면 제목 26px, KPI 36px. 데이터 숫자는 tabular-nums, ID는 monospace.
- 8px 기반 간격, 작은 모서리, 그림자 없음. 주요 컨테이너는 넓은 fluid 영역이며 작은 화면에서 열을 쌓는다.
- st.dataframe의 원본과 검증된 loader를 유지하고 UI에서 필요한 열만 먼저 보여준다. 원본 필드는 expander로 모두 확인한다.

## 보존 범위

Security Core, Adaptive D, A/B/C/D 정책, DTO, Evaluation 계산, 실제 실험 산출물·식별자는 수정하지 않는다. 공식 ASR/TSR/FPR=N/A, 정상/공격·Timeout/오류·ToolPolicy/Injection·모델/사용자 전달·실제/Fixture 구분을 유지한다. 새로운 성공률/Latency 값을 만들지 않는다.

## 검증 기록

실제 Chrome 158.0.8127.37 / Playwright에서 변경 전·후 5개 화면을 1920×1080, 1366×768로 캡처하고 가독성/레이아웃/조작을 점검했다. 기존 앱 브라우저 연결은 없었으므로 별도의 로컬 headless Chrome을 사용했다. 사용자의 기존 브라우저 프로필이나 전체 PC 화면은 제어하지 않았다.

- 두 해상도 × 5개 화면: 실제 메뉴 이동, URL 상태, 페이지/본문/흐름 텍스트 가로 넘침 없음, page error 없음.
- 키보드 ArrowRight 메뉴 이동, C 조건 실행 전 BLOCK과 실행 후 통제, Evidence 펼치기 통과.
- 원본 그래프 5개 탭 전환/alt text, CSV 다운로드 후 원본과 SHA-256 일치 통과.
- 390×844 및 reduced-motion 환경에서 Overview reflow/가로 넘침 검사 통과.
- 본문 대비 13.40:1, 보조 문구 5.89:1, ALLOW/BLOCK/WARN 텍스트 대비 각각 6.58/6.06/6.09:1. caption의 Streamlit 기본 opacity 0.6을 발견해 1로 수정하고 실제 computed style을 검사했다.
- 실제 캡처 확인 중 원본 표 머리글 줄바꿈과 실행 수 JSON 표기를 정리했다. 최종 집계 판정을 실행 이전 단계로 그리지 않고 선택 → SDK → 서버 → 모델 전달을 보여준다.
- 스크린샷은 차트 로딩과 이전 화면 stale DOM이 끝난 뒤 캡처하도록 QA 도구를 보완했다. 지표나 데이터를 바꿔 해결하지 않았다.

이는 Chrome headless의 지정 화면 및 상호작용 검증이며 전체 WCAG 인증이나 실제 발표용 프로젝터에서의 육안 검수를 뜻하지 않는다. 새 실모델 실행은 이번 UI 작업에서 수행하지 않았다.

## 스크린샷과 재현

[Before / After 화면 목록](assets/dashboard-redesign/README.md), [브라우저 QA 원본 결과](assets/dashboard-redesign/after/browser-qa.json).

```powershell
uv sync --locked --group dev --group demo
uv run streamlit run demo/final_dashboard.py --server.port 8502 --server.address 127.0.0.1 --server.headless true
```

http://127.0.0.1:8502 에서 확인한다. 기존 8501 서버는 Freeze 버전 비교용으로 유지했다. 재현 PC에서는 사용하지 않는 포트를 선택한다.

별도 터미널에서 실제 브라우저 QA:

```powershell
uv run --with playwright python scripts/check_dashboard_browser.py --url http://127.0.0.1:8502 --output-dir .cache/browser-qa
uv run pytest -q -ra
uv run ruff check .
git diff --check
```

Playwright는 opt-in QA 도구로만 사용하며 pyproject.toml/uv.lock 및 앱 runtime 의존성은 변경하지 않았다. 설치된 Chrome을 사용한다. HTML에 표시하는 Tool/기록 문자열을 escape하는 테스트, unknown/0 구분, 실행 전/후 경계 보존, URL deep link와 기본 접힘 상태 테스트를 추가했다. 최종 전체 QA 수와 dev SHA는 PR/최종 보고에 기록한다.

## web-design-guidelines 검수

`demo/research_ui.css` — caption opacity/대비 수정, focus-visible와 focus-within, reduced-motion, 긴 토큰 줄바꿈, 좁은 화면 grid reflow 확인.

`demo/research_ui.py` — semantic dl/ol/table, table scope와 region label, HTML escape, 색상과 텍스트 동시 표현 확인.

`demo/final_view.py` — h1→h2→h3, native radio/select/slider label·keyboard, URL view 상태, 이미지 alt·caption, 원본 상세 기본 접힘 확인. SVG/canvas 차트의 원본 숫자 표도 제공한다.

`scripts/check_dashboard_browser.py` — 실제 Chrome 상호작용과 지정 viewport 검사, 비율·화면 원본 JSON 보존. 전체 보조기술/브라우저 조합 검수는 별도 범위다.
