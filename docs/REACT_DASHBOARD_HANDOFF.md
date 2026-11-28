# GuardOn React Security Research Platform

## Skill audit와 적용 원칙 (구현 전)

`feat/presentation-react-20261127`, 기준 dev `ce81fbb47f19a20e6822a27422efbc0ed4722729`. 기존 Freeze와 Streamlit/Python 코드는 보존한다. 다섯 실제 SKILL.md를 읽고 다음처럼 적용한다.

| 스킬 | 설치·버전 | 이번 앱에서 적용 |
|---|---|---|
| redesign-existing-projects | 기존 전역 설치, 공식 taste-skill archive `73adb376…` | 실제 8503 화면 감사·Before 캡처 → 목록/상세 분리 → 정보 위계 재설계. 사용자 요청에 따라 새 React 앱으로 구현 |
| design-taste-frontend | 공식 `f6b76575…`, v2.5.1 신규 설치 | 한 시스템의 type/color/spacing, 실제 제품 UI와 사실 중심 문구, native 입력·focus·대비·equal edges. 마케팅 hero/사진/랜덤 deal/애니메이션 gate는 데이터 플랫폼 요구와 충돌해 적용하지 않으며 해당 gate 통과를 주장하지 않음 |
| minimalist-ui | 기존 전역 설치, 공식 archive `73adb376…` | 평면 탐색, hairline 구획, 반복 카드 제거, semantic status 이외 색 절제. 거대한 여백·장식 지시는 적용하지 않음 |
| UI/UX Pro Max | 기존 공식 설치 `72e5fc76…`, data/scripts 포함 | 실제 design-system 검색의 Data-Dense Dashboard 채택. 지원하는 도구에 variance=4/motion=1/density=8 전달. 잘못 매칭된 Enterprise Gateway 마케팅 구조는 제외. React focus 검색은 재검색해도 0건이므로 native dialog/keyboard 원칙을 일반 가이드에서 적용 |
| web-design-guidelines | 공식 `5a37a632…`, bundled command.md | React semantic table/dialog, focus 복귀·Escape, 보이는 label, unknown·대비·URL 상태·반응형·긴 ID 점검 |

스킬 설치는 전역 `.codex/skills`에서 수행했으며 프로젝트에 스킬 코드나 외부 데이터·인증 정보를 전송하지 않았다. UI/UX Pro Max README의 Codex 설치 경로를 이전 설치에서 확인했고 이번에 스킬/검색기를 다시 실행했다.

## Existing UI audit

최신 Streamlit `http://127.0.0.1:8503`를 Chrome headless에서 열고 5개 화면을 1920×1080/1366×768로 캡처했다(`docs/assets/react-dashboard/before`). 기존 구현은 여전히 다음 구조다.

- 큰 브랜드/저장 상태/라디오/화면 제목이 세로로 쌓여 분석 영역을 줄인다.
- 화면 이동마다 목록·실행 선택·근거가 분리되어 조사 맥락이 사라진다.
- 핵심 신호가 raw DTO 표와 반복 설명 사이에 묻힌다.
- Streamlit toolbar, native radio, 단일 문서 스크롤이 제품의 탐색 구조를 대신한다.

이번 앱은 기존 UI를 CSS로 옮기지 않고, 실행 목록·선택 Trace·조사 패널을 동시에 사용하는 정보 구조를 새로 구현한다.

## Design system과 화면 구조 (구현 전)

- Canvas off-white, 콘텐츠 white, ink charcoal/navy, 단일 muted teal accent. 오류/Timeout/차단은 텍스트와 semantic 색을 함께 표시한다.
- 232px 고정 sidebar, 56px context header, 28px 본문 제목, 15px UI 본문, 13px metadata, tabular 숫자·monospace ID. 4/8/12/16/24/32 간격 체계.
- KPI는 구분선만 있는 strip, 표는 semantic HTML, 관측 차트는 source count 기반 SVG. 기존 원본 PNG 그래프 5종은 변경 없이 gallery에서 조회한다.
- Overview: 코호트 KPI → 상태 차트/관측 경계 → 대표 실행 목록/정책 표.
- Agent Execution: 별도 Runtime/Benchmark source → 검색 가능한 실행 목록 → Candidate 단계 Trace → 우측 Evidence.
- Comparison: 동일 표본의 4조건 matrix, 현재 정책 정의와 과거 관측을 분리.
- Benchmark: 출처·변환, 분자/분모·scope·제외 사유, 원본 그래프·Latency·N/A.
- Evidence Explorer: Run/Trace/Tool 검색·condition/status 필터, Candidate 조사와 상세 panel.
- 우측 상세는 native dialog를 dock 형태로 사용해 focus trap/Escape/복귀를 보존한다. 검색·필터·선택은 URL에서 복원한다.

## 참고한 제품 패턴

시각 요소를 복제하지 않고 공식 설명의 조사 흐름만 참고했다.

- [Sentry traces](https://docs.sentry.io/product/trace-explorer/): 검색한 실행에서 span/속성으로 drill-down.
- [Grafana dashboards](https://grafana.com/docs/grafana/latest/visualizations/dashboards/): 공통 context와 source 지표를 연결한 분석 패널.
- [Linear](https://linear.app/features): 간결한 탐색·리스트 밀도.
- [GitHub Actions graph](https://docs.github.com/en/actions/how-tos/monitor-workflows/use-the-visualization-graph): 단계 상태와 선택한 단계의 기록을 연결.

## 데이터 경계

`presentation-ui/scripts/export_data.py`는 기존 `demo.actual_results.load_results()`로 먼저 정합성을 검사한다. 공개 관측표·Runtime public summary·출처 manifest만 내보낸다. 원본 모델 응답·Tool 인자·비공개 SQLite·키는 포함하지 않는다. 원본 파일 SHA-256 및 그래프/CSV byte 동일성을 보존한다. 공식 ASR/TSR/FPR은 원본 null/N/A다.

48시도와 Runtime 인계 29건은 별도 source이며 합산하지 않는다. ToolPolicy와 Injection, 모델 전달과 사용자 전달, 최종 집계와 개별 Output Guard, 완료와 과제 성공을 구분한다. 새 live inference 기능을 제공하지 않는다.

## 최종 구현·브라우저 반복 검증 · 2026-11-28

5개 화면을 모두 실제 공개 데이터에 연결했다. Trial/Trace/Tool 검색, 조건·상태·데이터셋 필터, URL 복원, 실행 목록 페이지 이동, Candidate 선택, Runtime/Benchmark source 전환, 같은 표본의 4조건 매트릭스, 조건/scope별 분모와 제외 사유, 공개 출처·변환·라이선스, 원본 PNG 5종·Latency, CSV 다운로드와 우측 Evidence를 제공한다. 원본 Run/Trace/Evidence ID를 유지하며 긴 값은 상세 패널에서 확인한다.

초기 React 화면을 캡처해 작은 메타데이터와 Trace 글자를 키우고 KPI·차트 간격을 줄였다. 실제 키보드 검사에서 select의 label에 option 문자열이 포함되는 것을 발견해 명시적 접근성 이름을 추가했다. 390px 검사에서는 표 안의 보조 설명이 스크롤 컨테이너 밖에서 배치되는 문제를 고쳤다. 표 자체는 필요한 경우 표 영역 안에서 가로로 스크롤한다.

`presentation-ui/src/App.tsx`, `styles.css`, `tokens.css`, `index.html`을 web-design-guidelines의 bundled command.md와 대조했다. native button/link/select/table/dialog, 보이는 데스크톱 label, 모바일 접근성 이름, skip link, focus-visible, Escape/focus 복귀, 상태 live region, 긴 ID wrapping, 이미지 크기·alt, reduced motion, semantic 상태색을 확인했다. 자동 WCAG 인증이나 마케팅용 design-taste gate 통과를 주장하지 않는다.

브라우저는 in-app runtime이 사용 가능한 브라우저를 반환하지 않아 사용자 요청에서 허용한 Python Playwright + 로컬 Chrome headless 158.0.8127.37로 검증했다. 개인 브라우저 프로필은 사용하지 않았다.

| 검사 | 최종 결과 |
|---|---|
| `npm.cmd run typecheck` | 통과 |
| `npm.cmd test` | 13개 통과. 데이터 계약·별도 집계·unknown/0·검색·조건/scope 해석 검증 |
| `npm.cmd run build` | 통과. JS 314.08 kB / gzip 94.14 kB, CSS 31.15 kB / gzip 7.04 kB |
| `npm.cmd run verify-data` | 48 Benchmark / 별도 Runtime 29 / 원본 그래프 5종 검증 |
| `uv run --project .. --with playwright python -X utf8 scripts/browser_qa.py` | 최종 production build에서 전체 통과. 5화면 × 2해상도, pageerror 0, 본문 가로 넘침 없음 |
| 브라우저 상호작용 | 실행 전/후 경계, Candidate, 상세/복사/Escape/focus, 검색/필터/빈 결과/새로고침, 지표 조건/scope, 원본 그래프/CSV byte 일치, 비교, 모바일, 실제 로딩 실패 처리 모두 통과 |
| `uv run pytest -q -ra` | **1356 passed, 2 skipped**, 154.00초. 기존 로컬 MCP 비교 Evidence 부재로 인한 2개 스킵 |
| `uv run ruff check .` / `git diff --check` | 통과 |
| 보호 대상 diff | 기준 `ce81fbb` 대비 src/shared/examples/tests/demo/benchmarks/reports/pyproject.toml/uv.lock/.streamlit 변경 없음 |
| Freeze | `guardon-freeze-20261127` → `4a569752a905666c1b52229edb52825b7a01b579`, 보존 |

실제 캡처와 검사 JSON은 [화면별 Before / After](assets/react-dashboard/README.md)에 모았다. 두 필수 해상도의 5화면과 우측 패널·모바일 이미지를 직접 검토했다. 재실행은 저장소 루트에서 아래 명령을 사용한다.

```powershell
cd presentation-ui
npm.cmd ci
npm.cmd run build
npm.cmd run preview
```

주소는 **http://127.0.0.1:5173**이다. 기존 8501·8502·8503 Streamlit과 별도 앱이다. 새 UI 브랜치는 `feat/presentation-react-20261127`이며 dev 대상 PR로 전달한다. 커밋 SHA와 PR 링크는 GitHub PR 및 최종 보고에 남긴다.

남은 구현 차단 문제는 없다. 자료의 한계는 남는다: 공식 ASR/TSR/FPR N/A, 과거 policy mode 및 개별 Guard/최종 사용자 전달 근거가 없는 필드 unknown, 공개 기록만 사용하는 Recorded/Replay 모드. 모바일 그래프는 원본 축소본이므로 상세 확대를 사용한다. CI에서 새로운 브라우저 실행을 자동화하는 workflow는 추가하지 않았으며 재현 스크립트와 실제 결과를 제공한다.

재현성을 위해 입력 SHA-256과 다운로드 CSV는 `git show HEAD:<source>`의 저장소 원본 byte를 기준으로 한다. 로컬 원본과 저장소 원본이 줄바꿈 외에 다르면 export를 거부한다. Windows `core.autocrlf`가 export 파일을 바꾸지 않도록 새 public/data 안에서만 `-text` 속성을 적용했다. 기존 입력 파일이나 저장소의 기존 `.gitattributes`는 수정하지 않았다.
