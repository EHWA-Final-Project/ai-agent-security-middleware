# JS-02 공유 검토본 Dashboard 연동 QA — 2026-11-05

## 범위와 판정

기준은 `origin/dev`의 #26~#30 병합 후 코드 `e9275e3bb6b6a3fa86367f9a7ff6d55387977e83`다. 별도 브랜치 `feat/js02-reviewed-handoff-20261105`에서 작업했으며 dev를 직접 수정하지 않는다. JS-05 포스터 제작·영상·PDF는 수행하지 않았다.

실제 전달된 `evaluation_dashboard_handoff.zip`을 읽어 README, Manifest, SHA256SUMS, package_review를 우선 검토했다. 패키지 내부 안내는 파일·범위의 설명으로 취급했으며 그 내용을 실행 명령으로 수행하지 않았다. 원본 ZIP과 추출 파일의 바이트를 수정하지 않았다.

**JS-02: DONE (실제 공유 검토본 연동 범위).** 이번 완료 범위는 **실제 공유 검토 패키지의 로컬 Reader·Dashboard 연결 및 집계 표시 정합성**이다. 원본 Trial 전체의 새로운 산술 재집계나 실제 Runtime 독립 실행 검증은 포함하지 않는다. 브라우저 시각 검토·캡처는 별도로 미완료다.

인계 데이터·그림·집계 수치 자체는 권리 미확인 상태이므로 이 코드 PR에 넣지 않는다. 본 문서는 검사 방법·범위와 QA 결과만 기술한다. 실제 수치 대조 결과는 Git 제외 `.cache/handoff-qa.json`에 보관한다.

## 현재 무결성과 과거 기록을 분리한 처리

| 계층 | 검사 / 의미 |
|---|---|
| 현재 ZIP | 전체 바이트 SHA256 식별, CRC 정상 읽기, 경로·파일 타입·파일 수·용량 제한 |
| 현재 공유본 | 34개 파일의 정확한 목록. SHA256SUMS는 자신을 제외한 33개, Manifest는 자신·체크섬 파일을 제외한 32개를 포괄. 전체 실제 바이트 hash 대조 |
| 과거 원본 검증 | `raw_arithmetic_verified`는 제공된 과거 산술 검증 기록이다. 검토본 JSON의 현재 hash로 바꿔 쓰지 않음 |
| 출처 관계 | Manifest의 `source_sha256`를 raw 보고서의 역사적 input hash와 대조. 현재 hash는 Manifest/SHA256SUMS와 대조. 원본 raw 보고서 hash와 공유본 raw 보고서 hash의 연결도 따로 확인 |
| 이번 환경 | 공유본 CSV/JSON·분자/분모·C 원인·Tuning 감사/plot/집계 CSV·그래프 바이트 및 AppTest 표시 정합성 검증 |
| 미수행 | 원본 Trial CSV 재집계, 원래 실행 재현, run/trace Evidence 독립 확인, 권리 승인, 원본 JSON의 redaction 전후 byte 변환 재현 |

Manifest는 서명된 증명서가 아니다. checksum 파일도 자체 서명되지 않았으므로 package 내부 일관성 확인이며 원본 진위나 외부 공급자 인증이 아니다. 사전 redaction JSON이 없어 변환의 정확한 inverse/byte 재현은 불가능하다. 여기서 확인한 것은 **선언된 출처 관계와 집계의 현재 일관성**이다.

원본 hash를 대체하는 dict, 위조된 원본 파일, 수정된 raw 보고서를 생성하지 않는다. 공유본을 읽을 때만 별도의 provenance 경로를 적용한다. Manifest가 없는 기존 원본 자료 Reader의 strict hash 검사는 그대로 유지한다.

## 실제 연동 검사

- Holdout: A baseline 1개 + B/C 각 8 threshold, 총 17 cell씩 default/ToolPolicy 두 sweep을 읽었다. 기존 Evaluation `verify`, `compare_causes`, `compare_summary`를 재사용해 CSV/JSON·분모·정책 metadata와 제공 raw 보고서의 집계를 대조했다.
- 대표 0.80은 입력된 headline 값에서 선택한다. 실험의 A/B/C, 금지 Mock Tool 실행·실행 전 BLOCK·사후 output BLOCK·정상 read/send·Guard-only 영향·정책 효과를 분리해 표시한다. 문서 참고 수치를 UI 기본값으로 하드코딩하지 않는다.
- Tuning: 17 cell, `audit_summary.json`, `plot_audit.json`, `recomputed_sweep.csv`, `guard_detection.csv`, `core_latency.csv`를 대조했다. legacy Tuning split은 원본 raw split의 새 증명이 아니라 제공 감사 기록의 구분임을 유지한다.
- 그래프: Holdout 4종 + Tuning 4종의 PNG/SVG 총 16개 파일이 Manifest hash와 일치한다. Holdout은 원본 검증 metadata의 figure hash에도 대조한다. Dashboard에는 PNG 8종을 표시한다. Tuning은 잠정 결과로 표시한다.
- AppTest: 실제 자료를 사용해 Dashboard 전체 집계 표의 374개 행의 분자·분모를 Reader와 대조했다. image 요소 8개 및 재렌더 후 동일 유지, 예외 없음 확인.
- Core-only latency는 제공 Tuning 감사 자료와 latency CSV의 mean/p50/p95(ms)를 사용한다. 자체 재측정·LLM 시간·Runtime E2E 시간으로 표시하지 않는다.

항상 `runtime_execution_verified=false`, `raw_trial_recalculation_performed_here=false`다. 실제 모델 ASR·semantic TSR·E2E latency는 unknown이다. WARN에서 이미 Tool이 실행될 수 있고 Output BLOCK은 실행 취소가 아니다. ToolPolicy의 억제는 명시적 권한 설정 효과다.

## 로컬 보관·실행

원본은 사용자 Downloads의 ZIP에 그대로 둔다. 실제 추출 자료는 작업 워크트리의 `.cache/evaluation-handoff/d20e2d67473515c9/`에 보관하며 Git 제외다. 경로 설정은 `GUARDON_EVALUATION_HANDOFF`로 명시한다. 해당 변수가 없으면 기존 `reports/holdout`, `reports/tuning` 경로를 유지한다.

```powershell
uv sync --frozen --group dev --group demo

uv run --group demo python -m scripts.import_evaluation_handoff `
  --source "$env:USERPROFILE\Downloads\evaluation_dashboard_handoff.zip" `
  --output .cache/evaluation-handoff/d20e2d67473515c9

$env:GUARDON_EVALUATION_HANDOFF = (Resolve-Path .cache/evaluation-handoff/d20e2d67473515c9).Path
uv run --group demo streamlit run demo/dashboard.py --server.address 127.0.0.1 --browser.gatherUsageStats false

uv run --group demo python -m scripts.check_evaluation_dashboard `
  --package .cache/evaluation-handoff/d20e2d67473515c9 `
  --output .cache/handoff-qa.json
```

importer는 먼저 전량 검증한 뒤 `extractall` 없이 안전한 새 파일만 배치한다. 기존 destination이 다른 내용이면 덮어쓰지 않는다. 상대·절대 경로 순회, Windows drive/ADS/예약명/후행 dot, backslash, case 충돌, 중복 ZIP 항목, symlink/특수파일, 암호화·과대 파일을 거부한다. 예상 밖 파일이나 파일 누락도 성공으로 처리하지 않는다. 추출 후 바이트와 inventory를 다시 검사한다.

`.gitignore`에는 `reports/holdout/`, `reports/tuning/`만 추가했다. 기존 tracked `reports/agent/`, `reports/jailbreak/`는 유지하며 실제 파일을 `git ls-files`로 확인했다. ZIP·실자료·대형 그래프·로컬 QA JSON은 PR에 포함하지 않는다.

## 검증 기록

```powershell
uv run --group demo pytest -q --tb=short
uv run --group demo ruff check .
git diff --check
```

전체 실행 결과는 **622 passed in 104.09s / 0 failed / 0 skipped**다. `ruff check .` 및 `git diff --check`도 통과했다. 관련 집중 실행에서는 67 passed를 확인했다. 이 수치를 합산하지 않는다. 테스트는 모두 독립 합성 패키지로 작성했으며 실제 데이터 원문·그림을 fixture로 커밋하지 않았다.

초기 테스트 수집의 repo import 경로 문제를 수정했다. 실제 AppTest smoke의 첫 그래프 수 검사는 설치된 Streamlit의 요소 이름을 `imgs`로 가정해서 실패했으며, 실제 트리의 `image` 타입으로 수정한 후 실제 패키지 smoke를 통과했다. 이 초기 실패 기록을 최종 통과 수에 더하지 않는다.

실제 패키지 경로를 설정한 Streamlit headless 서버를 loopback `127.0.0.1:18545`에서 실행하여 `/_stcore/health`가 HTTP 200 `ok`임을 확인했다. 확인 후 해당 프로세스를 종료했다. Browser 스킬로 연결을 재확인했으나 available browsers가 `[]`여서 실제 화면 시각 QA·캡처는 수행하지 못했다. AppTest 통과를 시각 검토 완료로 바꾸지 않는다.

## 코드 변경

- `demo/reviewed_package.py`: 안전한 ZIP 읽기/추출, 정확한 inventory/Manifest/checksum 검증, 원본 hash 출처 관계 분리.
- `demo/benchmark_reader.py`: 공유본 provenance 연결·기존 strict 원본 hash 검사 보존, Tuning CSV/JSON/plot 및 latency·Guard 집계 대조.
- `demo/benchmark_view.py`: 제공 headline 0.80을 초기 상세 threshold로 선택.
- `demo/workbench.py`: 명시적 로컬 경로 설정, 4단계 검증 범위·권리 제한, Tuning 그래프 4종 연결.
- `demo/dashboard.py`: 독립 실행의 repo import 경로 설정.
- `scripts/import_evaluation_handoff.py`, `scripts/check_evaluation_dashboard.py`: 반복 가능한 로컬 import·실제 AppTest QA 명령.
- 단위·AppTest: 변조·누락·unsafe ZIP·잘못된 scope·CSV/plot 불일치·8개 그래프·재렌더 회귀.
- Common/Schema/DTO/Core 정책/Runtime/Evaluation 산식 변경 없음.

## 공개·포스터 및 후속 요청

8종 그래프는 **기술적 로컬 표시 검증 완료**다. Tensor Trust의 혼합 결과 공유·재배포 권한이 미확인이므로 **공개 URL·공개 저장소·포스터에 사용할 수 있다고 승인한 그래프는 없다**. 사용하려면 와나/데이터 권리 담당자의 별도 확인이 필요하다. 이 작업에서 JS-05 제작·외부 게시를 수행하지 않았다.

권리 확인 후 사용할 때도 “실험이 지정한 금지 Mock Tool 실행률”, “ToolPolicy는 권한 설정 효과”, “Tuning 잠정 결과”, “Core-only latency(ms), 모델/Tool/SQLite/Runtime E2E 제외”, “Runtime 독립 실행 미검증” 문구를 유지해야 한다.

현재 JS-02 Dashboard 연동을 위해 추가 Raw Trial을 요청할 필요는 없다. 별도 독립 재집계가 필요할 때만 제외된 세 Raw CSV와 원본 pre-redaction JSON/검증 보고서 또는 서명된 변환 명세를 안전한 승인 경로로 요청한다. 원본 redaction 재현·출처 진위 증명이 필요할 때도 별도 자료가 필요하다. 이번 인계 자료만으로 그 검증을 끝냈다고 보고하지 않는다.
