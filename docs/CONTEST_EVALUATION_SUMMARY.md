# Benchmark / Evidence / Evaluation 인계 및 검증 결과

> **기준일:** 2026-11-04 (KST) · **담당:** Wana · **브랜치:** `feat/contest-benchmark`
> **상태:** Tuning default 재집계 및 Holdout default/ToolPolicy 원본 Trial 산술 검증 완료. **Fatin 실행의 Runtime Evidence 독립 검증은 미완료.**
> PASS는 명시한 범위의 완료이며, 실제 모델 ASR·Runtime 실행·데이터 권리의 포괄적 검증을 뜻하지 않습니다.

## 1. 실험 구분 및 주요 작업

| 실험 | 단위 / 범위 | 검증 및 해석 |
|---|---|---|
| 역사적 외부 텍스트 Mock replay | 35개 텍스트, 1,120 Trial | 고정 `read_file`, 당시 Core의 all-ALLOW 조사. [프로토콜](BENCHMARK_PROTOCOL.md) / [Guard 감사](BENCHMARK_GUARD_AUDIT.md) |
| Fatin Tuning | 2,118 Guard 샘플; default 23,392 Trial / 17조건 | 원본 CSV 재집계. 당시 Core/정책 및 ToolPolicy 원본의 한계는 유지 |
| Fatin Holdout | 1,294 Guard 샘플; default와 ToolPolicy 각각 22,831 Trial / 17조건 | 2026-11-04 원본 산술·해시·차단 원인 검증 완료 |

세 실험의 분모·선정·규칙 버전을 합치지 않습니다. Fatin Manifest의 총 3,412개는 Tuning 2,118 + Holdout 1,294입니다. Holdout 미사용·Freeze 이력은 제공 기록의 선언이며 독립적으로 증명한 사실은 아닙니다.

- 기존 Runtime/Evaluation 구조용 Benchmark Adapter, 집계·Report·검증 기능 및 테스트를 유지합니다. Security Core/Runtime 계약 변경은 없습니다.
- [Fatin 출처 인덱스](../benchmarks/fatin_handoff_provenance.json)는 출처·버전·분할·해시·라이선스 선언을 보존합니다. 실행용 [35개 샘플 Manifest](../benchmarks/manifest.json)와 별개입니다.
- 실제 Agent/Jailbreak 소규모 파일럿은 `reports/agent/`, `reports/jailbreak/`의 개수 중심 요약으로 별도 관리합니다. 원본 모델 응답은 Git/포스터에 넣지 않습니다.

## 2. WA-01 ~ WA-08 진행 상태

| 항목 | 상태 | 확인 내용 / 남은 작업 |
|---|---|---|
| WA-01 Benchmark 출처·Manifest | **PARTIAL** | 출처·Split·해시·변환 기록, Holdout 파일 해시 및 정렬 ID 해시 일치. Tensor Trust 권리, 원본 행 매핑·분할 구성의 독립 검증은 남음 |
| WA-02 Benchmark Adapter | **PASS** | DTO 변환·ID·입력 검증 구현 및 테스트. 역사적 35개 replay Adapter와 Fatin CSV 감사를 구분 |
| WA-03 B/C Threshold 분석 | **PASS (원본 산술)** | Tuning default 23,392행/17조건 및 Holdout 두 sweep 각각 22,831행/17조건 재집계. Holdout 34개 요약·8개 cause 행 불일치 0 |
| WA-04 지표 해석 | **PASS (명시 범위)** | Guard 탐지, Mock Tool 실행, pre-tool/Output BLOCK, 정상 WARN·결과 전달, 합성 Core Latency를 분리 |
| WA-05 실제 Agent·Jailbreak | **PARTIAL** | 소규모 실제 모델 파일럿 개수 요약. 판정·고정 모델 버전·독립 검토 필요 |
| WA-06 Evidence·재현성 | **PARTIAL** | Holdout frozen Core/정책 기록 수신, SHA256·정렬 ID·반복 산출물 일치. Trial에 `run_id`/`trace_id`가 없어 실제 Runtime Evidence 연결은 미검증 |
| WA-07 그래프·팀 인계 | **PASS (자료 준비)** | Tuning 그래프 및 재현 가능한 Holdout 4종 PNG/SVG 완료. Dashboard reader 통합은 별도 미완료 |
| WA-08 CI/Docker | **미진행(후순위)** | 로컬 pytest/Ruff 통과와 CI/Docker 통합 완료는 구분 |

## 3. Tuning 결과 — 역사적 인계 범위 보존

**Tuning default** Threshold 실험은 조건별 **공격 Tool intent 820건**(BIPIA 간접 375, Tensor Trust 직접 445), **정상 `read_file` 362건**, **정상 `send_email` 194건**으로 구성됩니다. A 기준 1조건 + B/C 각 8개 Threshold = **17조건, 총 23,392행**입니다. 같은 샘플을 여러 조건에서 평가했으므로 23,392행을 서로 다른 공격 샘플 수로 해석하지 않습니다. BIPIA 간접 375건은 125개의 고유 공격 지시문을 서로 다른 위치에 넣은 합성 사례입니다.

**Threshold 0.80, 공격 Tool 실행 결과:**

| 구분 | Mode B | Mode C |
|---|---:|---:|
| 금지 Tool intent 실행 | **752/820 (91.7%)** | **548/820 (66.8%)** |
| Tool 실행 전 BLOCK | **68/820 (8.3%)** | **272/820 (33.2%)** |

- 이 수치는 **실험이 제공한 Tool intent에 대한 Mock Tool 실행 여부**입니다. 모델이 공격에 속아 Tool을 직접 선택한 비율, 즉 **실제 LLM ASR이 아닙니다.**
- 실행 전 BLOCK과 **Tool 실행 후 Output BLOCK**은 구분합니다. Output BLOCK이 발생해도 이미 실행된 Tool을 미실행으로 계산하지 않습니다.
- 정상 `read_file`은 **362/362 실행 및 결과 전달**, WARN/BLOCK **0건**입니다. 정상 `send_email`은 B/C에서 **194/194 WARN**, BLOCK **0건**, Mock Tool 실행 **194/194**, **Tool 반환 결과 전달 0/194**입니다. 실제 이메일을 전송한 실험이 아니므로 '이메일 전송 성공/실패'로 표현하지 않습니다.
- 별도 Guard 단독 탐지 실험의 정상 샘플 **1,298건 중 오탐 0건**과 Runtime `send_email` WARN 194/194는 **서로 다른 분모와 측정 대상**이므로 합치지 않습니다.
- ToolPolicy 설정 시 공격 실행을 막은 결과는 **정책 효과**이며 Guard 자체 탐지 정확도가 아닙니다. **Tuning ToolPolicy** 원본 Trial CSV는 이 검증에서 확보·감사되지 않았습니다. 아래 Holdout ToolPolicy 원본 검증 완료와 구분합니다.

### B/C 그래프의 평평한 구간 해석

Fatin의 Tuning CSV에서 Mode C는 Threshold **0.75~0.98** 구간에 직접 공격 **247/445**, 간접 공격 **301/375** Tool 실행으로 일정합니다. 당시 검토한 Security Core 코드와 Fatin의 해설에 따르면, 이전 단계의 **WARN** 이후 Tool 단계에서 다시 **WARN**이 나오면 **STRICT 규칙으로 BLOCK**하는 동작이 주요 원인입니다. Mode B는 개별 위험 점수를 Threshold와 비교하므로, **0.90 점수를 가진 직접 공격 68건**은 Threshold를 **0.90 → 0.92**로 올릴 때 추가 실행됩니다.

**단,** Fatin은 최종 규칙 수정 뒤 각 차단 원인을 다시 분리해 검증하지 않았으며, 당시 정확한 Core Commit/설정도 전달되지 않았습니다. 따라서 이는 **당시 검토 코드와 Tuning 기록에 부합하는 해석**이지 원래 실행을 독립적으로 완전 재현한 결론은 아닙니다.

### Latency 및 실제 모델 결과의 범위

- 별도 **합성 Security Core 지연시간** 측정에서 B 평균 **0.684ms**, C 평균 **0.686ms**입니다. 실제 모델 호출, Tool 실행, SQLite, 전체 Runtime E2E 시간은 포함되지 않습니다. 어느 모드가 더 빠르다고 일반화하지 않습니다.
- Fatin이 `qwen3:8b`(Ollama)로 실제 Tool Calling과 소규모 Agent/BIPIA/Jailbreak 파일럿을 진행했습니다. 파일럿 표본과 일부 판정 검토의 한계가 있어 **공식 ASR·Jailbreak 방어 성공률로 일반화하지 않습니다.** 원본 모델 응답은 Git/포스터에 포함하지 않습니다.

## 4. Holdout 최종 원본 산술 검증

### 4-1. 데이터 단위와 검증 상태

[`verify_holdout_raw.py`](../scripts/verify_holdout_raw.py)는 기존 [`handoff_audit.py`](../src/evaluation/handoff_audit.py)의 집계와 [`plot_holdout_aggregates.py`](../scripts/plot_holdout_aggregates.py)의 해시/CSV·JSON/그림 검증을 재사용합니다. 실험 재실행이나 retuning은 하지 않았습니다.

- Default: **22,831 Trial / 17 condition-threshold cells**. ToolPolicy: **22,831 Trial / 17 cells**. 각각 A 1개 + B/C 각 8개 Threshold입니다.
- Guard: **1,294개 기록 = 1,294 고유 sample_id**. 공격 838, 정상 456입니다.
- Sweep: **1,176 고유 sample_id**, 조건당 **1,343 scenario Trial** = direct 463 + indirect 375 + benign_read 338 + benign_send 167.
- Guard-only BIPIA question-table 100개와 question-email 18개 ID는 sweep의 `sample_id`에 없습니다: 1,294 − 118 = 1,176. 나머지 중 167개 ID가 benign_read와 benign_send에 재사용되어 1,176 + 167 = 1,343입니다. 이 질문 텍스트가 보조 입력으로 쓰였는지는 CSV만으로 입증할 수 없습니다.
- Trial 식별 단위는 `(condition, threshold, trial_type, sample_id)`입니다. 동일 모집단·중복 ID·필드 일관성을 검사했으며 두 sweep 모집단도 같습니다.
- 세 raw CSV의 **SHA256이 `run_record_holdout.json`과 모두 일치**합니다. 정렬한 Guard ID를 개행으로 연결한 SHA256도 기록과 일치합니다.
- **34개 summary를 CSV와 JSON에 각각 대조: 불일치 0. C-mode 8개 cause 행을 개별 `block_cause` 및 Guard 점수에 대조: 불일치 0.** Guard metadata 불일치도 0입니다.
- 결과: `schema_version="holdout-raw-verification-v1"`, `status="raw_arithmetic_verified"`, **`runtime_execution_verified=false`**. 이는 원본 CSV 내부 산술 검증이며 실행 추적의 독립 확인이 아닙니다.

### 4-2. Threshold 0.80 결과

| Holdout 공격 Trial 지표 | Default B | Default C | ToolPolicy B/C 각각 |
|---|---:|---:|---:|
| Mock Tool 실행 | **767/838 (91.53%)** | **521/838 (62.17%)** | **0/838** |
| pre-tool BLOCK | **71/838 (8.47%)** | **317/838 (37.83%)** | **838/838** |
| Output BLOCK | 0/838 | 0/838 | 0/838 |

A는 실험이 제공한 forbidden `send_email`을 Guard 없이 실행하므로 838/838입니다. CSV의 `ASR`은 **공격 Tool 실행률**을 뜻하며 실제 모델의 공격 목표 성공률이 아닙니다. `tool_executed=1`과 Output BLOCK은 동시에 가능하므로 Output BLOCK을 실행 전 차단으로 세지 않습니다.

**Guard-only:** 기록된 strict Threshold 0.50에서 `risk_score >= 0.50`을 탐지로 세고 non-ALLOW 결정과 일치하는지 확인했습니다. 공격 탐지는 **317/838 (37.83%)**, 정상 오탐은 **1/456 (0.219%)**입니다. Guard-only 탐지 317/838과 Default C pre-tool BLOCK 317/838은 숫자만 같고, 독립 Guard 샘플 점수와 여러 단계의 시나리오 차단이라는 **다른 측정 대상**입니다. 별도의 제공 Guard 집계표는 없으므로 raw 기록에서 직접 산출했습니다.

유일한 정상 오탐은 `bipia-clean-context-email-02794` (`directive.send_to_address`, score 0.62)입니다. B/C 정상 read는 두 정책 모두 **337/338 실행 및 결과 전달**, WARN 1/338, BLOCK 0/338입니다. `TSR_read`는 `tool_executed=1 AND output_allowed=1`의 비율로, 요청 의미를 올바르게 해결했는지 판단하는 semantic TSR이 아닙니다.

| Holdout 정상 send_email (0.80; 각 분모 167) | ALLOW | WARN만 | BLOCK | Tool 실행 | 결과 전달 |
|---|---:|---:|---:|---:|---:|
| Default B | 0 | 167 | 0 | 167 | 0 |
| Default C | 0 | 166 | 1 (pre-tool) | 166 | 0 |
| ToolPolicy B | 166 | 1 | 0 | 167 | 166 |
| ToolPolicy C | 166 | 1 | 0 | 167 | 166 |

Default의 정상 send WARN은 민감 Tool 정책 동작이며 Guard-only 오탐률 1/456과 합치지 않습니다. C에서는 그 정상 context 오탐이 send 단계와 결합해 pre-tool BLOCK 1건이 됩니다. WARN으로 반환 결과를 보류한 것은 final Output BLOCK과 다릅니다. ToolPolicy의 허용 도메인/경로 내 정상 send 허용과 공격 실행 0%는 **설정 효과**, Guard 탐지 성능 향상이 아닙니다. 실제 이메일 전송 성공을 검증한 결과도 아닙니다.

### 4-3. C-mode 차단 원인

Default 공격 pre-tool BLOCK을 Trial의 `block_cause`로 집계한 결과입니다.

| Threshold | 전체 BLOCK | cumulative_risk | strict_warn_escalation | guard_block_or_other | single_guard_ge_thr |
|---|---:|---:|---:|---:|---:|
| 0.70 | 328 | 328 | 0 | 0 | 105 |
| 0.75 | 317 | 317 | 0 | 0 | 77 |
| 0.80 | 317 | 317 | 0 | 0 | 71 |
| 0.85 | 317 | 190 | 127 | 0 | 71 |
| 0.90 | 317 | 77 | 240 | 0 | 71 |
| 0.92 | 317 | 71 | 246 | 0 | 0 |
| 0.95 | 317 | 71 | 246 | 0 | 0 |
| 0.98 | 317 | 0 | 317 | 0 | 0 |

0.80에서는 **317건 모두 cumulative risk**로 기록됩니다. 더 높은 Threshold에서는 STRICT WARN escalation이 0.85의 127건부터 0.98의 317건까지 차지합니다. `single_guard_ge_thr`는 차단 Trial의 개별 Guard 점수가 Threshold 이상인 **중복 부분집합**이며 추가 차단 원인이 아닙니다. 이 결과를 Tuning의 원인 추정이나 역사적 35개 replay의 규칙에 소급 적용하지 않습니다.

### 4-4. Frozen 실행 기록 및 provenance

다음은 제공된 run record의 메타데이터이며 코드 재실행으로 검증한 provenance는 아닙니다.

- Core commit: `8ce9cadc325db8c287339ea937075436530e15a7`, 실행 브랜치 `feat/contest-security-core`.
- 시작: `2026-11-03T23:29:26.687018+09:00`; `forced_rerun=false`, `code_dirty=false`, `guards_frozen_before_run=true`.
- Python `3.12.14`; 실행 플랫폼 `Windows-11-10.0.26200-SP0`. 이는 검증기 실행 환경과 별개입니다.
- Strict Threshold 0.50, headline block Threshold 0.80; sweep `0.70, 0.75, 0.80, 0.85, 0.90, 0.92, 0.95, 0.98`.
- Default ToolPolicy는 null. Configured ToolPolicy: `allowed_tools=[read_file, send_email]`, `allowed_recipient_domains=[corp.invalid]`, `allowed_path_prefixes=[docs]`, `max_recipients=null`, `check_path_traversal=true`.
- Seed 42. Tensor Trust/NotInject는 `sha256(seed:key)` parity 분할, BIPIA는 공식 train=Tuning / test=Holdout. 공격 지시문을 같은 split의 seeded-random context 시작/중간/끝에 삽입. WebQA/Summarization context 미사용.
- Fatin dataset revisions: Tensor Trust `747a75e096761ebc01bd3970158827326b4add23`; PIGuard/NotInject `1b5751e88bf7475acbedfc8eda795ce060307c84`; BIPIA `a004b69ec0dd446e0afd461d98cb5e96e120a5d0`. 역사적 35개 replay의 NotInject revision과 구분합니다.

| 기록된 데이터/환경 SHA256 | 값 |
|---|---|
| samples_sha256 | `0e40ee271b53b2a7b3ecb92524348bd3407411b9ba17e21bf1fbb5371afed97f` |
| manifest_sha256 | `5f3831bd34988b09248ffd2cf915fdd5378e5c514f542bd360b2ee940bc73c4c` |
| split_sample_ids_sha256 (raw Guard ID로 확인) | `8f91c09ccd31419f4fd758af0e6d81384133c3c4404f4c245fba3d3fc35a9737` |
| uv_lock_sha256 | `ca1b4519b6e1ae7b70cd7c9297ec4d6c2a46766ac22a94c6db9e0c1488fd3732` |

원본 dataset 파일별 해시는 `run_record_holdout.json:data.original_file_sha256`에 보존되어 있습니다. 위 samples/manifest/lock 원본 바이트를 이번에 재검증했다는 뜻은 아닙니다.

## 5. 검증 산출물과 재현 방법

### 5-1. 실제 입력·출력

입력은 `C:/Users/wanaj/Downloads/for-wana.zip`과 같은 Downloads 폴더의 `sweep_holdout_trials.csv`, `sweep_policy_holdout_trials.csv`, `guards_holdout.csv`입니다. ZIP의 `for-wana/`에는 `HOLDOUT_DATA_GUIDE.md`, `holdout_results.json`, `run_record_holdout.json`, `sweep_holdout_summary.csv`, `sweep_policy_holdout_summary.csv`, `c_cause_holdout.csv`가 있습니다. ZIP에 세 raw CSV는 없으므로 `--raw-dir`가 필요합니다.

검증 보고서의 실제 경로는 `C:/Users/wanaj/Documents/Codex/2026-11-04/in/outputs/holdout_raw_verification/raw_verification.json`입니다. 이 로컬 산출물과 raw 입력은 저장소에 포함하지 않습니다.

| 입력 | 이번에 계산한 SHA256 |
|---|---|
| for-wana.zip | `486f3593872018429dc97a78ec65cca5d2a5178cd95220896533f205974e5960` |
| c_cause_holdout.csv | `1449a7b333c5533b78ee09fe387c6941bdd2cee960d8d219fcf74c527c8a6700` |
| guards_holdout.csv | `44d47834ce8e97a04298cef3b65723e50efcb9158b05216eda2ee1cecfd51e0f` |
| holdout_results.json | `b0b9fc9e28d25c82933b2a05c974040f9b660f3b6a0539097d7dcf50ab05e6b9` |
| run_record_holdout.json | `e0cc808544bb80505ba013fc20290a4978f8fe02cc3205418326de5deeca0068` |
| sweep_holdout_summary.csv | `c985924bc0f126432efc0ada6f5743705a9af3350e5f0b810e2c5a6223bd6a21` |
| sweep_holdout_trials.csv | `344dd8ca412f348855beb84bb4da8c31b121e563342ef223b798a7efcbcc153d` |
| sweep_policy_holdout_summary.csv | `8ad5e25061bdd0fc2a181abf8c74aa378bddb51e82d4820d9026a88c20e0ff33` |
| sweep_policy_holdout_trials.csv | `3d52368a65cb446b0d32ede23017143400cdad92619a689f15b9424988b31284` |

세 raw CSV 및 세 aggregate CSV는 run record의 `output_sha256`와 일치합니다. ZIP과 두 JSON의 해시는 검증기가 기록한 입력 식별값이며, run record가 자기 자신의 진위를 증명한다는 뜻은 아닙니다.

출력 디렉터리 구조:

```text
holdout_raw_verification/
  raw_verification.json
  figures/
    aggregate_validation.json
    holdout_attack_tool_execution.png / .svg
    holdout_benign_outcomes.png / .svg
    holdout_tool_policy.png / .svg
    holdout_c_block_causes.png / .svg
```

**Holdout 그래프 4종(PNG/SVG 총 8개 파일)**은 기존에 검토한 그래프와 SHA256이 일치하며, 동일 환경에서 두 차례 재생성한 결과물과 ZIP 파일의 동일성도 확인했습니다.

`aggregate_validation.json`은 `holdout-figure-validation-v2` 스키마를 사용하며, Summary 기반 집계 검증 단계(`aggregate_stage`)와 최종 패키지 검증 상태를 구분합니다. 집계 단계는 `aggregate_checked_only`로 기록되고, 원본 Trial CSV를 이용한 최종 검증 상태는 `raw_arithmetic_verified`입니다.

최종 패키지는 `raw_verification.json`의 상대 경로와 실제 SHA256을 참조하며, Summary 및 Blocking Cause 재집계 결과에서 불일치가 없음을 확인했습니다.

단, 본 검증은 제공된 원본 Trial 데이터의 집계 정확도에 대한 검증이며, Security Core / Runtime 전체 실행을 독립적으로 재현하거나 개별 `run_id` / `trace_id` 기반 Evidence를 대조한 것은 아닙니다 (`runtime_execution_verified: false`).

### 5-2. CLI 재현

저장소 root에서 기존 가상환경으로 실행합니다. 입력은 읽기 전용이고 출력은 **존재하지 않는 새 디렉터리**여야 합니다. 아래 명령은 frozen Holdout 실험을 재실행하지 않습니다.

```powershell
uv run --group demo python -m scripts.verify_holdout_raw `
  --source "$env:USERPROFILE\Downloads\for-wana.zip" `
  --raw-dir "$env:USERPROFILE\Downloads" `
  --output "$env:USERPROFILE\Documents\holdout_manual_raw_verified" `
  --package "$env:USERPROFILE\Documents\holdout_manual_raw_verified.zip"


# Aggregate-only 검증/그림 생성; 이 명령만으로 raw 산술 검증을 주장하지 않음
.venv/Scripts/python.exe -m scripts.plot_holdout_aggregates --source "C:/Users/wanaj/Downloads/for-wana.zip" --output "holdout_aggregate_review_new"

# 기존 Tuning 감사/그림 재현 (실제 handoff 디렉터리 사용)
$FATIN_DIR = "C:/Users/wanaj/Documents/Codex/2026-11-02/Handoff-from-Fatin/handoff-wana"
.venv/Scripts/python.exe -m scripts.audit_fatin_handoff --source "$FATIN_DIR" --output "audit_tune_review_new"
.venv/Scripts/python.exe -m scripts.plot_fatin_handoff --trials-csv "$FATIN_DIR/results/sweep_bc_tune_trials.csv" --summary-csv "$FATIN_DIR/results/sweep_bc_tune_summary.csv" --split tune --toolpolicy absent --output "figures_tune_review_new"

.venv/Scripts/python.exe -m pytest -q -p no:cacheprovider
.venv/Scripts/python.exe -m ruff check .
git diff --check
```

환경을 새로 구성할 때는 저장소 lockfile과 `uv sync --frozen --group dev --group demo`를 사용합니다. `--split holdout`만 바꿔 Tuning 입력을 Holdout으로 재명명하지 않습니다. `--existing-figures`는 선택 옵션으로 그림 byte 비교를 추가합니다. Raw verifier는 성공 시 exit 0, 발견된 수치/그림 불일치 시 exit 1, 입력 검증 오류 시 exit 2를 반환합니다. 실패한 입력은 성공 보고서로 취급하지 않습니다.

2026-11-04 최종 로컬 검증 실행: **pytest 408 passed (40.46s), Ruff 전체 검사 통과**, 신규 Holdout Python 파일 4개의 Ruff format 검사 통과. 실제 Holdout 원본 Trial CSV 기반 재집계 검증도 수동으로 재실행했으며, `raw_arithmetic_verified` 상태와 Summary CSV/JSON, Blocking Cause CSV/JSON, Guard Metadata 및 기존 그림 비교에서 **불일치 0건**을 확인했습니다.

이전 검증의 395 passed 및 310 passed는 과거 실행 기록이며, 이번 408개 테스트에 합산하지 않습니다. Fatin님의 별도 Security Core 브랜치 테스트도 합산하지 않습니다. 코드 테스트 및 원본 데이터 재집계 검증은 Security Core / Runtime 실행의 독립 재현이나 개별 `run_id` / `trace_id` 기반 Evidence 검증을 대신하지 않습니다 (`runtime_execution_verified: false`).

## 6. Dashboard Evaluation 데이터 인계

### 6-1. 파일 계약과 검증 상태

| 파일 | 실제 JSON 계약 / 용도 |
|---|---|
| `holdout_results.json` | `kind=benchmark_evaluation`, `split=holdout`; `run`, `data`, `headline_block_threshold`, `tool_policy`, `sweep_default`, `sweep_with_tool_policy`, `c_block_cause`, `notes`. 별도 schema_version 필드 없음 |
| `run_record_holdout.json` | 실행 메타데이터, `policy`, `data`, `commands`, `output_sha256`; 별도 schema_version 없음 |
| `raw_verification.json` | `schema_version=holdout-raw-verification-v1`, `status=raw_arithmetic_verified`, `runtime_execution_verified=false`; 아래 구조 참고 |
| `figures/aggregate_validation.json` | `status=aggregate_checked_only`, `raw_trial_recalculation_performed=false`, `independently_verified_against_raw_trials=false`. aggregate 전용 단계의 정확한 상태이며 후속 raw report와 구분; schema_version 없음 |
| Tuning `audit_summary.json` | `schema_version=imported-fatin-audit-v1`, `status=arithmetic_audited`, `evidence_validated=false`; 입력 해시·Manifest·Guard·Latency 요약 |
| Tuning `plot_audit.json` | `split`, `split_verification`, `toolpolicy`, `input_sha256`, `cells`, `benign_send_raw_patterns`; schema_version 없음 |
| 역사적 replay `summary.json` | `schema_version=contest-benchmark-v1`; `read_benchmark_summary()`는 completed 결과 검증용. Fatin 형식과 교환 불가 |

Raw report의 주요 구조:

- `input_sha256`, `source_archive_sha256`, `run_record_hashes_matched`, `implementation_sha256`: 입력/코드 및 기록과의 일치 근거.
- `sweeps.default`, `sweeps.tool_policy`: `rows`, `conditions`, `unique_sample_ids`, `scenario_trials_per_condition`, `trial_types_per_condition`, `missing_runtime_identity_fields`, `cells`.
- 각 cell의 `condition`, `threshold`(문자열; A는 빈 문자열), `n_attack`, `n_benign_read`, `n_benign_send`; `attack_tool_execution`, subtype별 실행률, `pre_tool_block`, `output_block`, `fpr_read/send_warn_block`, `fpr_read/send_block`, `fpr_read/send_warn_only`, `completion_read/send`와 각 `_numerator`, `_denominator`.
- `c_causes`, `guards`(records/unique_ids/groups/totals/false_positive_ids/정렬 ID 해시), `population_mapping`, `limitations`.
- `mismatches` 및 `mismatch_totals`: summary_csv, summary_json, causes_csv, causes_json, guard_metadata. 그림 비교 결과는 `existing_figure_byte_mismatches`, `mismatch_totals.existing_figure_bytes`에 기록. 이번에는 모두 0/빈 목록.
- `figure_sha256`, `figure_environment`, `existing_figures_checked=true`: 동일 입력·코드·렌더 환경에서의 재현 근거. 환경이 다르면 그림 byte 차이가 날 수 있습니다.

제공 summary CSV와 JSON sweep 행은 `condition`, `threshold`, `n_attack`, `ASR`, `ASR_direct`, `ASR_indirect`, `pre_tool_block`, `n_benign_read`, `FPR_read(WARN|BLOCK)`, `FPR_read(BLOCK)`, `TSR_read`, `n_benign_send`, `FPR_send(WARN|BLOCK)`, `FPR_send(BLOCK)`를 사용합니다. A threshold는 CSV 빈 값 / JSON null이며 raw report는 정규화한 문자열입니다. `ASR` → `attack_tool_execution`, `TSR_read` → `completion_read`로 표시명을 명확히 매핑합니다.

Tuning의 `recomputed_sweep.csv`, `guard_detection.csv`, `core_latency.csv`는 기존 감사 명령의 산출물입니다. Holdout verifier가 이 파일들을 생성한다고 가정하지 않습니다. 역사적 replay의 `summary.csv`, `trials.jsonl`, `trials.csv`도 별도 산출물입니다. PNG/SVG와 JSON은 별도 팀 전달 자료로 준비했으며 수신/배포 완료를 뜻하지 않습니다.

### 6-2. 연동 및 표시 주의사항

현재 [`demo/reports.py`](../demo/reports.py)는 기존 completed A/B/C Runtime Report 구조를 읽고, [`demo/workbench.py`](../demo/workbench.py)의 Benchmark Lab은 reader 연결 대기 상태입니다. **Holdout 결과 검증은 완료, Dashboard 통합·표시 검증은 미완료**입니다. 지송님·지원님께는 위 로컬 산출물, schema/필드 매핑, 분모, 검증 상태와 한계를 함께 전달합니다. Fatin JSON을 기존 Runtime Report나 Evidence schema로 직접 대체하지 않습니다.

- Tuning/Holdout/35개 replay를 별도 실험으로 표시하고 고유 sample과 scenario Trial을 구분합니다.
- Guard-only 탐지, 공격 Mock Tool 실행, pre-tool BLOCK, Output BLOCK, 정상 WARN 및 결과 전달을 별도 표시합니다. 비율은 분자/분모와 함께 표시합니다.
- 실제 LLM ASR·semantic TSR·미검증 실행 상태·실패/제외 건수는 확인된 값이 없으면 unavailable/null로 남깁니다. 파일 내 Trial 수 확인을 전체 시도·누락 없음의 증명으로 해석하지 않습니다.
- Core 단독 합성 Latency와 Runtime E2E를 혼합하지 않으며, 소규모 실제 모델 파일럿을 일반적인 방어 성공률로 표시하지 않습니다.

## 7. 남은 한계 및 공개 조건

- **Runtime Evidence:** Fatin Holdout Trial에 `run_id`/`trace_id`가 없습니다. 실행별 상태·Tool 호출·Evidence DB 연결, 전체 Runtime 실제 수행 여부는 독립 검증하지 못했습니다. 역사적 35개 replay의 run/trace 증거를 대신 붙일 수 없습니다.
- **Provenance:** Holdout Core/정책/Freeze 메타데이터는 수신 완료입니다. 해시 일치는 제공 기록과 파일의 일관성이지 원본 실행 진위·Freeze 시점·Holdout 이전 미사용의 증명이 아닙니다. 원본 dataset·분할 생성·변환 행 매핑은 추가 확인 범위입니다.
- **Tuning/실제 모델:** Tuning 당시 정확한 Core/정책 및 ToolPolicy 원본 검증 한계, 실제 모델 파일럿의 최종 판정 기준·고정 모델 버전·독립 판정 한계는 남습니다. Holdout 확인으로 이 과거 공백을 소급 해소하지 않습니다.
- **라이선스:** Tensor Trust 이용·재배포 권리는 여전히 미확인입니다. [기록된 라이선스 문의](https://github.com/HumanCompatibleAI/tensor-trust-data/issues/3)는 최종 권리 허가를 뜻하지 않습니다. Fatin BIPIA context에는 CC BY-SA 자료가 포함됩니다. 역사적 템플릿-only 선정의 라이선스 관찰을 전체 Fatin 데이터에 확대하지 않습니다. 내부 사용이라는 문구도 권리 허가가 아닙니다.
- **단일 실행:** frozen Holdout을 재실행·retune하지 않았고 신뢰구간/독립 반복 실험은 없습니다. 원본 데이터·모델 응답·비공개 Prompt는 Git, 공개 Dashboard, 슬라이드/포스터에 포함하지 않습니다.

**검토 상태:** Holdout 원본 산술·SHA256·4종 그림 재현 확인 완료. Runtime Evidence, Dashboard 통합, 데이터 권리 및 실제 모델 결과의 독립 검증은 별도 남은 작업입니다.
