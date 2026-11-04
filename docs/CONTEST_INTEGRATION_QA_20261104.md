# GuardOn 통합·독립 QA — 2026-11-04 KST

사용자 요청에 따라 Downloads의 `GuardOn_Codex_Integration_Prompt_20261104.md`를 검토하고 P0 구현·검증을 진행했다. 기존 워크트리와 중첩 저장소는 보존했다. Common/Schema/Core/Runtime 계약·규칙·Threshold는 변경하지 않았다.

## 기준과 원격 검토

- 원래 워크트리: `dev`, `62442413c6492e83454785747d25cecb2ec3578c`. 기존 untracked 중첩 저장소 존재.
- 작업 위치: `.worktrees/guardon-integration`, 브랜치 `feat/guardon-integration-qa-20261104`.
- 작업 기준: fetch 후 `origin/dev`, `69b2814308822758b71431bbacfcb03a1a82f8e9` (#27 merge).
- #26: open / non-draft, head `ac4752cd43687b6cfbdefc56d3ccd0bf2f1c4104`.
- #27: merged, head `2f673b89562eb91ef15b309479b1ae2703550dc4`.
- #28: open / draft, head `f559d1d08b5470992a42c84e630a5a96ff576719`.
- `git merge-tree --write-tree origin/dev origin/feat/multi-step-agent-pilot` → exit 0、tree `e4ff23b7111257075f2a7ccd28a1b33b6dd9e473`.
- `git merge-tree --write-tree origin/dev origin/feat/contest-benchmark` → exit 0、tree `2379816da62dde746c8de46aaae9f847a4700015`.
- 충돌 검사만 수행했다. PR #26/#28을 작업 브랜치에 병합하거나 해당 변경을 덮어쓰지 않았다. 두 PR 상호 간 최종 통합 테스트는 아직 아니다.
- #27/#28의 이력에는 Agent 예제·LLM client·pilot·관련 테스트가 중복된다. 현재 dev 기준 #28의 실제 차이는 README, Runtime 평가 문서, Agent 예제 3개, LLM/pilot 테스트 2개다. 충돌이 없다는 사실이 의미적 통합을 보장하지 않는다.

계약 소스는 #26 head의 `docs/CONTEST_EVALUATION_SUMMARY.md` 및 `scripts/verify_holdout_raw.py`, `scripts/plot_holdout_aggregates.py`, `src/evaluation/handoff_audit.py`를 Git으로 직접 읽었다. 해당 문서는 아직 dev에 없으며 복제하지 않았다. PR 상태는 연결된 GitHub 도구로 확인했다.

## 작업 상태

| 작업 | 상태 | 구현·검증 근거 / 남은 항목 |
|---|---|---|
| JS-01 B/C·Replay | DONE (합성 Mock 범위) | 기존 세 Runtime 카드와 Replay 유지. `demo/service.py`의 `run_comparison()`이 기존 조건별 factory로 B/C 각각 실행·저장. 별도 run_id/trace_id, policy_version, 출력, 호출 횟수·Evidence 표시. 재렌더 시 재실행 없음 테스트 |
| JS-02 Benchmark Reader | PARTIAL | `demo/benchmark_reader.py`, `demo/workbench.py`: 순수 Reader와 UI 연결, 검증 상태·분모·제공 분자·분리된 ToolPolicy 차트. 실제 Holdout/Tuning 파일 미수신으로 실제 자료 일치·비교 차트·실측 캡처 미완료 |
| JS-03 Plugin 확장 | DONE (코드·계약 범위) | 현재 Registry의 name/stage/enabled 패널 재사용. 기존 Custom Guard 등록·중복 거부·비활성화·B/C 누적 차이·실패 격리 테스트 실행. SVG 2개 추가. 서비스 hot-swap 기능이라는 주장은 하지 않음 |
| JS-04 독립 QA | PARTIAL | 현재 dev + 본 변경의 pytest/Ruff 및 Streamlit health 검증. #26/#28 최종 조합 미병합·미검증. 브라우저 화면 캡처 미완료 |
| JS-05 포스터 인계 | PARTIAL | `POSTER_VISUAL_ASSET_REQUEST.md`와 SVG 준비. Holdout 원본 기반 4종 그림·실측 화면·최종 포스터 디자인/PDF는 미수신·미제작 |

## Reader 동작과 검증 한계

- 최상위 Holdout JSON에 schema_version을 요구하지 않는다. `kind`, `split`, run/data 등 인계 필드와 headline 0.80을 검사한다.
- 두 sweep은 각각 A baseline 1개 및 B/C × 8 threshold의 17 cell을 요구한다. 숫자/문자열 threshold는 정규화하되 잘못된 문자열, 중복 cell, bool, 비정수 count, NaN, 무한대, 잘못된 split, 누락 필드, 잘린 JSON을 거부한다.
- 0분모는 null 비율만 허용한다. 원본 검증 cell이 없으면 분자를 추정·반올림하지 않고 unknown으로 남긴다.
- `raw_verification.json`이 있으면 알려진 schema/status, runtime_execution_verified=false, mismatch 합계 0, Holdout JSON·run record SHA256, cell별 분모·분자·summary 비율의 일관성을 비교한다.
- 표시 상태는 결과 없음 / 스키마 불일치 / 검증 불충분 / 제공 산술 검증 메타데이터 일치다. 마지막 상태도 원본 Runtime 실행 재현이나 Evidence 검증을 의미하지 않는다.
- 이 Reader는 원본 CSV 재집계 검증기를 대체하지 않는다. raw 보고서의 출력·정상 WARN/BLOCK 및 completion 등 원본 세부값은 별도 expander에서 제공 메타데이터로 표시한다. Summary의 TSR_read는 의미적 성공률이 아니다.
- SHA256은 수신 바이트의 식별·일관성이다. 원래 실행의 진위·Freeze·분할 무결성·데이터 권리를 증명하지 않는다. 그래프는 존재할 때만 표시하며 현재 Reader는 이미지 바이트의 진위를 독립 검증하지 않는다.
- Tuning 감사 JSON과 역사적 35샘플 replay 안내는 별도 패널이다. 360 Trial 합성 Fixture는 기존 Evaluation 탭에 남는다. Tuning/Holdout 자동 비교 차트는 실제 파일 인계 후 보강할 항목이다.
- Downloads의 이름을 한정해 조사했으나 Holdout/Tuning 인계 파일은 발견하지 못했다. 다른 사용자의 `C:/Users/wanaj/...` 경로를 접근하거나 전역 파일 탐색을 하지 않았다.

## 변경 파일

| 파일 | 역할 |
|---|---|
| `demo/benchmark_reader.py` | Streamlit 없는 read-only Holdout adapter |
| `demo/workbench.py` | Holdout/Tuning·역사적 replay 분리 및 실제 B/C 비교 패널 |
| `demo/service.py` | 기존 시나리오 실행 재사용, 조건별 B/C 실행 helper |
| `demo/dashboard.py` | 비교 패널 연결만 추가 |
| `demo/plugin_view.py` | 기존 Registry 패널에 Custom Guard 예제·계약 테스트 시연 동선 추가 |
| `tests/unit/test_benchmark_reader.py` | 합성 정상·오류·hash·raw 집계 일관성 테스트 |
| `tests/integration/test_plugin_dashboard.py` | 누락 상태 갱신, Reader UI·B/C ID 격리·재렌더 테스트 |
| `docs/assets/poster/guardon_architecture.svg` | 코드 기반 아키텍처 도식 |
| `docs/assets/poster/guardon_plugin_registration.svg` | Plugin 등록·비활성화·검사 흐름 |
| 본 문서와 `POSTER_VISUAL_ASSET_REQUEST.md` | QA 증거 및 포스터·시연 인계 |

## 실행 및 검증 기록

실행 위치는 명시한 작업 워크트리다. 아래 최종 결과는 후속 검증 기록에 기재한다.

```powershell
git status --short
git branch --show-current
git remote -v
git log -5 --oneline
git fetch origin
git diff --check
git worktree add -b feat/guardon-integration-qa-20261104 .worktrees/guardon-integration origin/dev
git diff --name-only origin/dev...origin/feat/multi-step-agent-pilot
git diff --name-only origin/dev...origin/feat/contest-benchmark
git merge-tree --write-tree origin/dev origin/feat/multi-step-agent-pilot
git merge-tree --write-tree origin/dev origin/feat/contest-benchmark
uv sync --frozen --group dev --group demo
uv run --group demo pytest -q --tb=short
uv run --group demo ruff check .
```

추가 실행:

- `.venv/Scripts/python.exe -m pytest tests/unit/test_benchmark_reader.py -q`: 첫 실행은 Windows 임시 폴더 권한으로 21 setup errors. 승인된 환경으로 재실행하여 해소했다. 코드 실패로 합산하지 않는다.
- 초기 `uv sync`와 `git fetch`도 sandbox cache/.git 권한 오류 후 승인된 환경에서 성공했다.
- 첫 전체 테스트: **432 passed**, skip/fail 0. 이후 Reader UI 테스트 추가 후 관련 테스트 **32 passed**. 이 숫자는 합산하지 않는다.
- `uv run --group demo ruff format demo/benchmark_reader.py demo/workbench.py tests/unit/test_benchmark_reader.py`.
- `uv run --group demo ruff check demo/dashboard.py --fix`: import 포맷 수정. 오류 로깅 보강 후 전체 Ruff 통과.
- Streamlit: `.venv/Scripts/python.exe -m streamlit run demo/dashboard.py --server.headless=true --server.address=127.0.0.1 --server.port=18541 --browser.gatherUsageStats=false`; Python 표준 urllib로 `/_stcore/health` **HTTP 200, ok** 확인 후 프로세스 종료.
- Browser 스킬로 캡처 연결 시도: `iab` unavailable, available browsers `[]`. 다른 브라우저 자동화로 우회하지 않았다. 실제 캡처·시각적 QA 완료로 표시하지 않는다.
- SVG는 벡터 소스를 직접 생성했다. 화면 렌더 검토 여부는 후속 기록에 명시한다.
- GitHub Actions 실행은 확인하지 않았으며 CI 통과를 주장하지 않는다.

## Blocker·담당자·통합 순서

1. Wana/Fatin: `holdout_results.json`, `run_record_holdout.json`, raw 보고서·figures 패키지, Tuning 감사 자료를 실제로 인계. SHA256·분모·정상 send 제한을 확인한 뒤 실측 화면 및 split 비교 제작.
2. 소유자 리뷰: #26 Evaluation, #28 Runtime draft를 각각 검토. #27은 이미 병합됨. 충돌 없는 dry-run 결과를 근거로 최종 merge를 자동 승인하지 않는다.
3. 승인 후 통합 담당자: dev + #26 + #28 + 본 PR 최종 조합을 별도 브랜치에서 전체 pytest/demo health로 검증. 이번 결과를 최종 조합의 결과로 재사용하지 않는다.
4. 브라우저 사용 가능 환경에서 BENIGN/PRE-BLOCK/POST-OUTPUT-BLOCK, B/C 비교, Registry, Evidence, 실제 Holdout 화면 캡처. SVG 레이아웃 시각 검토.
5. 데이터 권리·공개 URL 확인 후 집계 자산만 포스터로 인계. 원본 데이터·DB·모델 응답은 제외.

실제 Holdout Runtime Evidence 연결과 실제 LLM 공격 차단 효과는 미검증이다. Core/Runtime 버그가 확인된 것은 없으며 소유자 계약을 변경하지 않았다.

## 최종 자체 검증 결과

- `uv run --group demo pytest -q --tb=short`: 최종 재실행 **435 passed in 22.38s**, **0 skipped / 0 failed**. 현재 dev + 본 작업 범위이며 #26/#28 통합 결과가 아니다.
- `uv run --group demo ruff check .`: **All checks passed**.
- `git diff --check`: exit 0. LF/CRLF 변환 안내는 공백 오류가 아니다.
- `uv run python examples/custom_guard.py`: 정상 예제 ALLOW risk=0.0, 합성 금지어 예제 WARN risk=0.9. Manager 등록과 직접 inspect 예제이지 Runtime 차단 자체의 증거는 아니다. 차단·B/C·비활성화·실패 격리는 전체 계약 테스트에서 확인했다.
- `/_stcore/health`: HTTP 200 `ok`, 확인 후 서버 종료.
- SVG 2개 모두 XML 파싱 성공, viewBox `0 0 1440 620`. 시각 렌더 검토는 미완료다.
- SVG SHA256: architecture `b17b90bcba681b803c1980962a84cb94e38e7e4dd46c91af9b877a02f6c80fff`, plugin registration `31657f3b7c839e87043830bf9a5d617abb4472cd24a5647497ec89c0cdac51f0`.
- 추가 UI 안내 후 `uv run --group demo pytest tests/integration/test_plugin_dashboard.py -q --tb=short` 단독 실행에서 11 passed / 1 failed: 새 테스트가 전체 수집 시 추가되는 sys.path에 의존했다. fixture의 demo 경로를 사용하는 import로 수정했고 최종 전체 검사를 재실행했다. 제품 Runtime 오류가 아니며 실패 기록을 최종 통과 수에 합산하지 않는다.
- 수정 후 동일 UI 단독 명령: **12 passed in 4.96s**, skip/fail 0.
- 최종 commit SHA는 인계 메시지 및 해당 PR head를 기준으로 식별한다. 문서 자체에 자기 commit의 SHA를 삽입하지 않는다.
