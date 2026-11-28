# Dashboard branding · 2026-11-28

기준 dev `60e7477`. 기능 변경 없이 브랜딩만 정리했다.

## 변경 파일과 구조

- `presentation-ui/public/branding/guardon-mark.svg`: 평면 단색 shield/G 모노그램. 채워진 사각형 타일 대신 열린 여백과 각진 방패 외곽을 사용한다.
- `presentation-ui/public/branding/ewha-symbol.png`: 사용자가 제공한 학교 심볼 원본 그대로. 재그리기·크롭·색 변경 없음.
- `presentation-ui/public/branding/README.md`: 학교 SVG 교체 방법과 자산 출처.
- `presentation-ui/src/Branding.tsx`: 재사용 가능한 BrandMark / ProjectCredit. 학교 심볼 로딩 실패 시 이미지가 빠지고 학교 텍스트는 남는다.
- `presentation-ui/src/App.tsx`: 두 브랜딩 컴포넌트를 사이드바에 삽입했다. 라우팅·검색·데이터 로직은 변경하지 않았다.
- `presentation-ui/src/styles.css`: 얇은 구분선, 절제된 크레딧 글자, 원본 이미지 비율 유지. 짧은 화면에서는 사이드바 내부 스크롤을 허용한다.
- `presentation-ui/index.html`: favicon도 동일한 새 SVG를 참조한다.

추천 배치(구현): 사이드바 하단의 Recorded 안내 아래에 학교 심볼/학교명, GuardOn Team, 오지송 · 이지원 · Fatin · Wana. 분석 본문과 헤더는 그대로다.

대안(미구현): 본문 최하단에 학교명과 팀원을 작은 한 줄 attribution으로 배치한다. 사이드바가 없는 독립 보고서/임베드 화면을 추가할 때 적합하다.

발표용 정보 위계는 제품명 → 프로젝트 목적 → 분석 탐색 → 자료/모드 → 제작 주체 순서로 정리했다. 상단의 WORKSPACE/Graduation project 중복을 한글 ‘졸업 프로젝트’로 통합했다. 하단은 아카이브와 Recorded 안내를 묶고, 학교/팀 크레딧만 얇은 선으로 구분한다. 팀원은 두 줄로 고정해 좁은 폭에서도 읽기 편하게 했다. 모바일은 상단 breadcrumb의 화면명 대신 GuardOn을 표시하고, 현재 화면 제목은 본문에서 그대로 보여준다. 헤더에 추가 배지나 학교 정보를 중복 배치하지 않았다.

## 스킬 적용

design-taste-frontend: 기존 type/color 체계와 실제 브랜드 자산, 일관된 정렬을 적용했다. minimalist-ui: 그림자·그라데이션 없는 평면 SVG와 hairline 크레딧을 적용했다. 마케팅 hero/애니메이션 등은 이번 사용자의 기능 보존·브랜딩 한정 요구와 맞지 않아 적용하지 않았으며 마케팅 gate 통과를 주장하지 않는다.

## 검증

- TypeScript / Vite Pages build 통과, 기존 Vitest 13개 통과.
- 실제 Chrome: 1920×1080, 1366×768, 1024×600, 390×844에서 브랜드 자산 로드·화면 가로 넘침 없음 확인. 좁은 화면에서는 메뉴를 열어 크레딧을 확인했다.
- Pages 하위 경로에서 로고/학교 PNG 및 favicon HTTP200, Evidence 검색/조건 필터·빈 결과와 학교 이미지 오류 fallback 검증.
- [1920 캡처](assets/branding/after-1920x1080.png), [1366 캡처](assets/branding/after-1366x768.png), [짧은 화면](assets/branding/after-1024x600.png), [모바일 메뉴](assets/branding/after-390x844.png).
- Python/Core/Runtime/평가/공개 데이터/워크플로 변경 없음. 기존 앱에는 별도 다크 테마가 없어 테마 동작을 추가하거나 변경하지 않았다.

## 로컬 및 Pages

이 브랜치의 presentation-ui에서 `npm.cmd ci`, `npm.cmd run build -- --mode pages`, `npm.cmd run preview -- --mode pages --port 5174`.

미리보기: http://127.0.0.1:5174/ai-agent-security-middleware/

배포는 기존 dev push workflow의 `--mode pages`를 유지한다. React는 BASE_URL, favicon은 %BASE_URL%를 사용한다. 배포 완료 후 `/branding/guardon-mark.svg`와 `/branding/ewha-symbol.png`가 저장소 하위 URL에서 로드되는지 확인한다. 탭 아이콘이 캐시되어 보이면 강력 새로고침 또는 새 탭에서 확인한다. Pages에는 PR 병합 후 배포 workflow 성공이 필요하다.
