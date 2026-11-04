# GuardOn 최종 PR 통합 및 JS-01~JS-04 검증

2026-11-04 KST. 사용자 요청으로 #26 → #28 → #29의 dev 병합을 승인받아 실행했다. JS-05는 범위에서 제외했다. 실제 Holdout/Tuning 파일은 Wana의 개인 PC에만 있고 현재 공유 링크가 없다는 사용자 확인을 받았다. 다른 사용자의 로컬 경로에 접근하지 않았다.

## GitHub 및 안전한 작업 환경

| 대상 | 최종 확인 상태 | SHA |
|---|---|---|
| #27 Security Core | 이번 작업 전 dev 병합 완료 | merge `69b2814308822758b71431bbacfcb03a1a82f8e9` |
| #26 Evaluation | merged, 2026-11-04 18:24:09 KST | head `ac4752cd43687b6cfbdefc56d3ccd0bf2f1c4104`; merge `b9270a6f8ab4570af019ca72d0e8115afe68406e` |
| #28 Runtime | Draft 해제 후 merged, 18:24:59 KST | head `f559d1d08b5470992a42c84e630a5a96ff576719`; merge `b84900fcf82a4d57ff90d36c501d3cd637a5459b` |
| #29 Workbench/QA | 수정 커밋 추가 후 merged, 18:25:20 KST | head `ba772c6dd6813ca770c7a36a63c824821cdb3401`; merge `a2486e780347be603b23cace441b8d878c45acfb` |
| dev 코드 검증 HEAD | 실제 원격 병합 결과, 아래 전체 테스트 직접 실행 | `a2486e780347be603b23cace441b8d878c45acfb` |
| main | 변경 없음; 시작/종료 확인값 동일 | `0fcef1161624f9c8ded5366d691b21f831c7a894` |

시작 origin/dev는 `69b2814308822758b71431bbacfcb03a1a82f8e9` (#27 merge)였다. #14는 병합하지 않았다. 원래 root dev 워크트리와 중첩 저장소 및 기존 worktree/untracked 파일을 삭제·초기화하지 않았다. 검증은 `.worktrees/guardon-final-qa`에서 수행했다.

GitHub 최신 PR 상태·head·변경 파일·리뷰·commit status·workflow를 각각 조회했다. 세 PR의 reviews/status/check rollup은 빈 목록이었다. 보호 규칙 API는 private 저장소 요금제 제한 403으로 조회할 수 없었다. `gh pr view`의 CLEAN 상태를 확인하고 일반 GitHub merge API에 expected_head_sha를 지정했다. 관리자 우회·force·보호 규칙 수정·직접 dev/main push는 사용하지 않았다. GitHub가 세 병합을 정상 수락한 후 closed/merged 및 merge SHA를 다시 확인했다.

GitHub Actions workflow 파일 및 조회 가능한 해당 commit workflow/status가 없었다. **CI 통과가 아니라 로컬 통합 검증 통과**다.

## 사전 통합과 최소 수정

```powershell
git fetch origin
git worktree add -b integration/guardon-final-qa-20261104 .worktrees/guardon-final-qa origin/dev
git merge --no-ff origin/feat/contest-benchmark -m "test integration: PR 26 evaluation"
git merge --no-ff origin/feat/multi-step-agent-pilot -m "test integration: PR 28 runtime"
git merge --no-ff origin/feat/guardon-integration-qa-20261104 -m "test integration: PR 29 workbench"
```

세 merge는 충돌 없이 성공했다. #27/#28에는 과거 Core 커밋이 중복되지만 최신 dev 기준 #28의 실제 추가 변경은 Agent/client/pilot·Runtime 문서·해당 테스트의 7개 파일이었다. `shared`, `src/runtime`, `src/security`, `pyproject.toml`, `uv.lock`는 시작 dev와 최종 통합 사이 변경이 없다. 기존 정책·threshold·공통 DTO·평가 산식을 수정하지 않았다.

초기 통합 실행 588 passed 후 Ruff가 Dashboard import 정렬을 지적했다. #26의 `reports/` 패키지 추가에 따른 정렬 차이를 최소 수정했다. Reader를 Evaluation 검증기에 직접 연결하는 추가 테스트에서 fixture의 정책 메타데이터 및 검증기 tuple 반환 연결 오류를 발견해 수정했다. 최종 통과 결과와 초기 실패 결과를 합산하지 않는다.

추가 코드 커밋은 통합 브랜치 `1a08f587c9a86103962ae556deb6e0ebb4349d23`, #29 반영본 `ba772c6dd6813ca770c7a36a63c824821cdb3401`이다. 두 커밋의 코드 변경은 동일하다. 추가 push는 자동 승인 검토에서 새 payload 승인 부족으로 한 차례 거절됐으며, 사용자의 해당 커밋 명시적 승인 후 push했다.

## JS-01~JS-04 완료 판정

| 작업 | 판정 | 직접 확인한 근거 |
|---|---|---|
| JS-01 B/C·Evidence Replay | **DONE — 합성 Mock 범위** | 같은 scenario/Mock 입력을 B/C로 각각 실행, 별도 run/trace, 정책 버전, Guard 점수·결정·실행·출력·SQLite 연결. 정상/사전 BLOCK/사후 BLOCK 경계 matrix. AppTest에서 재렌더 시 재실행 없음. 중복 Replay 보존 및 누락 Evidence 경고 |
| JS-02 Benchmark Lab | **PARTIAL — 실제 인계 대기** | Reader/UI/오류 테스트 및 Evaluation 검증기 연동 완료. 실제 Holdout/Tuning 파일·4종 그래프 미수신으로 실데이터 수신·원본 SHA·화면 수치 대조 미완료 |
| JS-03 Plugin 확장 | **DONE — 현행 Registry 범위** | 기존 인터페이스·등록·중복·활성화/비활성화·stage·priority·오류 격리·B/C 계약과 기존 4 Guard 회귀 통과. `PLUGIN_QUICKSTART.md` 추가. 기존 SVG 구조와 코드 흐름 대조 |
| JS-04 통합 QA | **DONE — 명시 검증 범위** | 세 PR 실제 병합, 원격 dev checkout 후 597 passed / 0 skipped / 0 failed, Ruff·diff·Streamlit health 통과. Runtime/Evidence·Mock Agent E2E·AppTest 포함. 시각 QA·실제 모델 공격 효과는 별도 한계 |
| JS-05 | **범위 외** | 11/5 오지송·이지원 공동 진행. 이번 라운드에서 포스터·영상·제출 PDF를 제작하지 않음 |

### 실제 구현된 보강

- `demo/benchmark_reader.py`: #26 소유 `compare_causes`, `verify`, `validate_raw_report`를 재사용. 제공 CSV 패키지가 완전할 때 원본 hash·CSV/JSON 집계·C 원인·raw report를 교차 확인한다. 원본 CSV 집계 검증기를 중복 구현하거나 실행 검증으로 격상하지 않는다.
- `demo/benchmark_view.py`: Experiment Overview, Threshold·사전/사후 차단, C 차단 원인, 정상 read/send 영향, 정책, 검증 상태를 별도 표로 표시한다. 고유 표본·Trial·Guard-only 분모는 제공 metadata에서만 읽는다. 없는 값은 unknown이다.
- `demo/workbench.py`: 검증 metadata와 SHA가 맞는 PNG만 표시한다. Tuning 감사 split/state/mismatch를 검사하고 제공된 Core-only mean/p50/p95(ms)를 표시한다. 누락 파일은 수치로 대체하지 않는다.
- `demo/plugin_view.py`: Decision/Execution/RunStatus Evidence가 빠진 경우 저장 확인으로 표시하지 않는다. Replay 중복 이벤트를 보존하며 ID/시각 누락은 기록 없음으로 처리한다. STRICT를 추정하지 않는다.
- `tests/unit/test_benchmark_reader.py`: 합성 fixture로 실제 Evaluation 검증기와 Reader 계약을 연결, CSV 변조·그림 변조·외부 경로 파일명·메타 hash 불일치·Tuning split/불일치 거부 검증.
- `tests/integration/test_plugin_dashboard.py`: B/C 세 경계 시나리오의 같은 입력·독립 ID·실제 SQLite 및 Evidence 이벤트 연결, 누락·중복 처리 검증.
- `docs/PLUGIN_QUICKSTART.md`: Custom Guard 등록/비활성화/priority/실패 정책/조건 연계를 코드 기준으로 설명한다.

## 실제 검증 명령 및 결과

```powershell
uv sync --frozen --group dev --group demo
uv run --group demo pytest -q --tb=short
uv run --group demo ruff check .
git diff --check
```

| 실행 대상 | 결과 |
|---|---|
| 최초 세 PR 조합 | pytest 588 passed; Ruff import 오류 발견 후 수정 |
| 보강된 Reader·Dashboard 집중 실행 | 42 passed, 이후 Ruff 통과 |
| 사전 통합 최종 코드 `1a08f58` | **597 passed in 77.42s**, **0 failed / 0 skipped**; Ruff 통과; diff 통과 |
| 실제 병합된 dev `a2486e7` | **597 passed in 60.53s**, **0 failed / 0 skipped**; Ruff 통과; diff 통과 |

개별 PR의 408/400/435 결과를 합산한 것이 아니다. Streamlit demo 의존성을 설치했으며 과거 streamlit 미설치 skip은 최종 실행에 없다. `git diff --exit-code 1a08f58 origin/dev`도 성공하여 사전 검증 코드 tree와 실제 병합 결과가 일치함을 확인했다.

최종 dev 검증 명령:

```powershell
git fetch origin
git switch -c qa/guardon-dev-final-20261104 origin/dev
uv sync --frozen --group dev --group demo
uv run --group demo pytest -q --tb=short
uv run --group demo ruff check .
git diff --check
```

Streamlit은 각 검증 단계에서 loopback 전용 headless 서버를 실제 실행했다. 최종 dev에서는 `.venv/Scripts/python.exe -m streamlit run demo/dashboard.py --server.headless=true --server.address=127.0.0.1 --server.port=18543 --browser.gatherUsageStats=false` 후 `http://127.0.0.1:18543/_stcore/health`가 **HTTP 200 `ok`**를 반환했다. 확인 후 서버는 종료했다. AppTest는 실제 실행·상태·표시 정합성을 검증한다. Browser runtime의 available browsers는 `[]`여서 시각 QA·실제 화면 캡처는 하지 못했다.

전체 테스트에는 Common/Runtime contract, SQLite Evidence, 조건 A/B/C, ToolPolicy 허용/금지 도구·경로, 오류/timeout fail-closed, Agent Mock·로컬 fake LLM server, Custom Guard·Registry priority, Benchmark raw 산술/집계·그림 검증, Streamlit AppTest가 포함된다. 실제 외부 이메일·외부 LLM 호출·배포는 수행하지 않았다.

## Holdout·Agent·성능의 검증 한계

실제 인계 파일은 사용자 확인에 따라 Wana의 로컬 PC에 있으며 현재 PC에서 접근할 수 없다. 실제 파일 이름과 전달 구조·재현 CLI는 `CONTEST_EVALUATION_SUMMARY.md`의 계약을 따른다. 임의로 결과 JSON/Raw CSV를 만들지 않았다. 테스트 fixture는 테스트 전용 합성 자료이며 공식 Holdout으로 배치하지 않았다.

```text
reports/holdout/                 # 수신한 실제 파일만 배치; Git 커밋 제외
  holdout_results.json
  run_record_holdout.json
  sweep_holdout_summary.csv
  sweep_policy_holdout_summary.csv
  c_cause_holdout.csv
  raw_verification.json
  figures/
    aggregate_validation.json
    holdout_attack_tool_execution.png / .svg
    holdout_benign_outcomes.png / .svg
    holdout_tool_policy.png / .svg
    holdout_c_block_causes.png / .svg
reports/tuning/                  # 별도 감사 산출물
  audit_summary.json
  plot_audit.json
```

다운로드 받은 zip/별도 raw CSV는 검증 스크립트의 `--source`, `--raw-dir`에 명시적으로 지정한다. frozen 실험을 재실행하거나 retune하지 않는다.

```powershell
uv run --group demo python -m scripts.verify_holdout_raw --source <received-for-wana.zip> --raw-dir <received-raw-directory> --output <new-verification-directory>
uv run --group demo streamlit run demo/dashboard.py --server.address 127.0.0.1 --browser.gatherUsageStats false
```

Benchmark Lab에 실제 인계 디렉터리를 지정하고 파일 hash·split·17 cell/sweep·분모·원인 count·그림 hash·표시값을 대조한다. 아직 수행하지 못한 실데이터 검증 단계다.

- `runtime_execution_verified=false`를 유지한다. Holdout Trial에는 run_id/trace_id가 없어 합성 Runtime Evidence를 대신 연결하지 않는다.
- B/C 71/838·317/838 및 Tool 실행 767/838·521/838 등은 #26 문서 참고치일 뿐 이번 PC에서 직접 실자료로 확인한 값이 아니다. UI에 하드코딩하지 않았다.
- Mock Tool intent 실행률은 실제 LLM ASR이 아니다. completion은 의미적 TSR이 아니며 ToolPolicy의 차단은 권한 설정 효과다. WARN에서 Tool은 실행되고 반환 결과만 보류될 수 있다.
- 실제 Ollama 파일럿은 재실행하지 않았다. #28의 기록상 금지 send_email 요청이 발생하지 않은 실험을 Guard 차단 성공으로 계산하지 않는다. 이번 검증은 scripted Mock Agent와 fake HTTP LLM 서버를 포함한다.
- Core-only latency는 제공 감사 자료의 ms 단위 mean/p50/p95만 표시한다. LLM·Tool·SQLite·Runtime E2E 시간을 합치거나 문서 참고값을 측정치로 채우지 않는다.
- SHA는 제공 파일 간 일관성이지 원본 실행 진위·분할 Freeze·데이터 권리 증명이 아니다. 원본 데이터·모델 응답·로컬 DB는 Git에 넣지 않는다.

## 진행률 및 제출 전 남은 일

진행률의 전체 작업 분모가 없으므로 프로젝트 전반의 임의 백분율은 제시하지 않는다. 객관적으로 계산 가능한 JS-01~04 엄격 완료율은 **3/4 = 75%**이며 JS-02의 부분 구현을 완료로 합산하지 않는다. JS-05까지 다섯 항목으로 세면 완료는 3/5지만 이번 통합 범위 진행률과 섞지 않는다.

| 구분 | 증거 기반 상태 / 추정의 한계 |
|---|---|
| Security Core | 현행 P0 코드·계약 회귀 통과. 실제 모델 방어 효과 및 전체 연구 과제 진행률은 산정 불가 |
| Runtime / Enforcement | Mock P0 연결·오류·timeout·출력·Agent E2E 완료. 실제 모델 공격 효과 미확정 |
| Evidence / Evaluation | 코드·raw 산술 검증기·단위 QA 통합 완료. 이 PC의 실제 파일 수신·실데이터 검증 대기 |
| Workbench | JS-01/03 완료, JS-02 Reader/UI 준비·실데이터 연동 PARTIAL |
| Integration / QA | 요청된 세 PR 병합 및 최종 dev 직접 검증 완료 |
| 11/6 경진대회 준비 | 구현·통합 근거 확보. 실제 자료 연결 및 11/5 포스터·영상·PDF 작업은 남음; 전체 준비율 산정 불가 |
| 졸업프로젝트 전체 | 범위·전체 계획·제출 요건의 분모 미확인으로 백분율 산정 불가 |

1. **Wana → Jisong:** 실제 Holdout/Tuning 인계 패키지·원본 raw CSV·해시·그림 전달. Jisong이 JS-02 실자료 검증 및 UI 수치 대조 후 DONE 판정.
2. **Jisong / Jiwon:** 브라우저 사용 가능한 환경에서 시각 QA 확인. 별도 JS-05는 11/5 공동 수행하며 이번 라운드에서는 작업하지 않음.
3. **포스터 사용 가능 근거:** 최종 dev의 597 통과·Mock Runtime 경계 동작·Evidence 연결은 확정된 자체 QA 사실이다. 보안 탐지율/실제 모델 방어율은 아니다. Holdout 수치·그래프는 실제 파일 인계·대조 및 출처/권리 확인 후 사용한다.

이 문서의 코드 기준 SHA는 실제 세 PR 병합 결과를 고정한다. 문서만 추가하는 후속 PR의 merge SHA는 GitHub 및 최종 인계 메시지에서 확인할 수 있으며 문서에 자기 commit SHA를 삽입하지 않는다.
