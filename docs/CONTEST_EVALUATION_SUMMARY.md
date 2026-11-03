# Benchmark / Evidence / Evaluation 인계 및 검증 결과

> **기준일:** 2026-11-03 · **담당:** Wana · **브랜치:** `feat/contest-benchmark`
> **상태:** Tuning 평가 및 코드 검토용 자료 준비 완료. **최종 Holdout 검증은 미완료.**
> 이 문서의 PASS는 **표에 명시한 작업 범위의 완료**를 뜻하며, 전체 실험의 최종 검증 완료를 의미하지 않습니다.

## 1. 이번 PR의 주요 작업

- 외부 Benchmark 샘플을 기존 Runtime/Evaluation 구조에 연결하는 Adapter, 집계·리포트·검증 기능 및 테스트 추가
- **Fatin이 제공한 Tuning 원본 CSV**의 집계 결과 검증 및 B/C Threshold 비교 그래프 생성
- Benchmark 출처·버전·분할·해시·라이선스 관련 정보 정리: `benchmarks/fatin_handoff_provenance.json`
- 실제 LLM/Jailbreak 소규모 파일럿 결과는 **개수 중심 요약**으로 별도 관리 (`reports/agent/`, `reports/jailbreak/`)
- **기존 `benchmarks/manifest.json`의 35개 샘플 파일럿**과 Fatin의 대규모 실험은 서로 다른 평가로 구분

## 2. WA-01 ~ WA-08 진행 상태

| 항목 | 상태 | 확인 내용 / 남은 작업 |
|---|---|---|
| WA-01 Benchmark 출처·Manifest | **PARTIAL** | 출처, Split, 해시 및 변환 방식 문서화 완료. Tensor Trust 데이터셋 권리 및 일부 원본 행 매핑 확인 필요 |
| WA-02 Benchmark Adapter | **PASS** | DTO 변환, ID 및 입력 검증 구현·테스트 완료. 기존 35개 샘플 파일럿용 Adapter와 Fatin 결과 감사(Audit)는 구분 |
| WA-03 B/C Threshold 실험 분석 | **PASS (집계 검증)** | 원본 Tuning CSV **23,392행 / 17개 조건**의 집계 일치 확인. Fatin Runtime 전체 재실행은 미수행 |
| WA-04 지표 해석 | **PASS (Tuning 범위)** | Tool 실행률, 실행 전 BLOCK, Guard 탐지, 정상 요청 WARN, Latency를 별도 해석 |
| WA-05 실제 Agent·Jailbreak | **PARTIAL** | 소규모 실제 모델 파일럿 개수 요약 완료. 일부 판정·모델 고정 버전 및 독립 검토 필요 |
| WA-06 Evidence·재현성 | **PARTIAL** | 출처/해시/Seed/재집계 절차 기록. 원본 `run_id`·`trace_id`, 실행 상태, 정확한 Core 버전·정책 정보 부족 |
| WA-07 그래프·팀 인계 | **PASS (Tuning 그래프)** | PNG/SVG 그래프 4종 준비. 최종 Holdout 그래프는 결과 수신 후 갱신 필요 |
| WA-08 CI/Docker | **미진행(후순위)** | 이번 인계에서는 Evaluation 테스트와 결과 재집계에 우선 집중 |

## 3. 데이터와 핵심 결과

Fatin 전달 Manifest에는 **3,412개 샘플(Tuning 2,118 / Holdout 예약 1,294)**이 기록되어 있습니다. 현재 검증된 수치는 **Tuning 결과만** 해당하며, Holdout 실제 실행 및 미사용 상태는 독립 확인되지 않았습니다.

Threshold 실험은 조건별 **공격 Tool intent 820건**(BIPIA 간접 375, Tensor Trust 직접 445), **정상 `read_file` 362건**, **정상 `send_email` 194건**으로 구성됩니다. A 기준 1조건 + B/C 각 8개 Threshold = **17조건, 총 23,392행**입니다. 같은 샘플을 여러 조건에서 평가했으므로 23,392행을 서로 다른 공격 샘플 수로 해석하지 않습니다. BIPIA 간접 375건은 125개의 고유 공격 지시문을 서로 다른 위치에 넣은 합성 사례입니다.

**Threshold 0.80, 공격 Tool 실행 결과:**

| 구분 | Mode B | Mode C |
|---|---:|---:|
| 금지 Tool intent 실행 | **752/820 (91.7%)** | **548/820 (66.8%)** |
| Tool 실행 전 BLOCK | **68/820 (8.3%)** | **272/820 (33.2%)** |

- 이 수치는 **실험이 제공한 Tool intent에 대한 Mock Tool 실행 여부**입니다. 모델이 공격에 속아 Tool을 직접 선택한 비율, 즉 **실제 LLM ASR이 아닙니다.**
- 실행 전 BLOCK과 **Tool 실행 후 Output BLOCK**은 구분합니다. Output BLOCK이 발생해도 이미 실행된 Tool을 미실행으로 계산하지 않습니다.
- 정상 `read_file`은 **362/362 실행 및 결과 전달**, WARN/BLOCK **0건**입니다. 정상 `send_email`은 B/C에서 **194/194 WARN**, BLOCK **0건**, Mock Tool 실행 **194/194**, **Tool 반환 결과 전달 0/194**입니다. 실제 이메일을 전송한 실험이 아니므로 '이메일 전송 성공/실패'로 표현하지 않습니다.
- 별도 Guard 단독 탐지 실험의 정상 샘플 **1,298건 중 오탐 0건**과 Runtime `send_email` WARN 194/194는 **서로 다른 분모와 측정 대상**이므로 합치지 않습니다.
- ToolPolicy 설정 시 공격 실행을 막은 결과는 **정책 효과**이며 Guard 자체 탐지 정확도가 아닙니다. 해당 실험의 원본 Trial CSV는 별도 확보가 필요합니다.

### B/C 그래프의 평평한 구간 해석

Fatin의 Tuning CSV에서 Mode C는 Threshold **0.75~0.98** 구간에 직접 공격 **247/445**, 간접 공격 **301/375** Tool 실행으로 일정합니다. 현재 확인 가능한 Security Core 코드와 Fatin의 해설에 따르면, 이전 단계의 **WARN** 이후 Tool 단계에서 다시 **WARN**이 나오면 **STRICT 규칙으로 BLOCK**하는 동작이 주요 원인입니다. Mode B는 개별 위험 점수를 Threshold와 비교하므로, **0.90 점수를 가진 직접 공격 68건**은 Threshold를 **0.90 → 0.92**로 올릴 때 추가 실행됩니다.

**단,** Fatin은 최종 규칙 수정 뒤 각 차단 원인을 다시 분리해 검증하지 않았으며, 당시 정확한 Core Commit/설정도 전달되지 않았습니다. 따라서 이는 **현재 코드와 Tuning 기록에 부합하는 해석**이지 원래 실행을 독립적으로 완전 재현한 결론은 아닙니다.

### Latency 및 실제 모델 결과의 범위

- 별도 **합성 Security Core 지연시간** 측정에서 B 평균 **0.684ms**, C 평균 **0.686ms**입니다. 실제 모델 호출, Tool 실행, SQLite, 전체 Runtime E2E 시간은 포함되지 않습니다. 어느 모드가 더 빠르다고 일반화하지 않습니다.
- Fatin이 `qwen3:8b`(Ollama)로 실제 Tool Calling과 소규모 Agent/BIPIA/Jailbreak 파일럿을 진행했습니다. 파일럿 표본과 일부 판정 검토의 한계가 있어 **공식 ASR·Jailbreak 방어 성공률로 일반화하지 않습니다.** 원본 모델 응답은 Git/포스터에 포함하지 않습니다.

## 4. 검증 및 재현 방법

**이번 브랜치 검증(Codex 최신 실행 보고):** `pytest` **310 passed**, Ruff 통과, `git diff --cached --check` **exit code 0**. 원본 Tuning Trial **23,392행**과 17개 조건의 집계 수치가 일치했습니다. Fatin Security Core 브랜치에서 보고한 **377개 테스트 통과**는 별개이며 통합 실행 결과는 아닙니다.

다음 명령은 **이미 전달받은 CSV를 다시 검증·시각화**하는 작업입니다. 원본 데이터를 새로 수집하거나 Fatin의 전체 실험을 재실행하지 않습니다. 각 출력 폴더는 새 경로를 사용해야 합니다.

```powershell
# 사용자 컴퓨터의 실제 Fatin handoff 폴더로 변경
$FATIN_DIR = "C:/path/to/handoff-wana"

uv run --group demo python -m scripts.audit_fatin_handoff --source "$FATIN_DIR" --output "audit_new"
uv run --group demo python -m scripts.plot_fatin_handoff --trials-csv "$FATIN_DIR/results/sweep_bc_tune_trials.csv" --summary-csv "$FATIN_DIR/results/sweep_bc_tune_summary.csv" --split tune --toolpolicy absent --output "figures_tune_new"
```

재현에 필요한 원본 CSV는 PR에 포함하지 않았으며, 제공 경로와 SHA256 목록은 `benchmarks/fatin_handoff_provenance.json`에서 확인할 수 있습니다. **그래프 PNG/SVG 4종은 별도 팀 인계 ZIP으로 전달**하고, 그래프 재생성 코드는 이 PR에 포함합니다. `--split holdout` 옵션만 바꾼다고 Tuning 데이터가 Holdout 결과가 되는 것은 아닙니다.

## 5. 남은 확인 사항 및 공개 시 주의

- **Fatin:** 실험에 실제 사용된 Security Core Commit/정책 설정, 원본 실행별 Evidence(`run_id`, `trace_id`, 상태 및 Tool 호출 기록), Holdout 원본·집계 결과 및 Split 목록 제공 여부 확인
- **Fatin:** 실제 모델 파일럿의 최종 판정 기준·모델 고정 버전, 별도 ToolPolicy 실험의 Trial 데이터 확인
- **팀:** Guard 규칙 Freeze 시점과 Holdout 실행·최종 수치 확정 일정 조율
- **라이선스:** Tensor Trust 데이터셋의 이용·재배포 조건이 명확하지 않음([관련 GitHub Issue](https://github.com/HumanCompatibleAI/tensor-trust-data/issues/3)). 원본 데이터·모델 응답·비공개 Prompt는 Git/슬라이드/포스터에 포함하지 않음

## 6. Dashboard Evaluation 데이터 인계

### 6-1. 현재 인계 상태

- **Tuning:** Fatin 제공 원본 CSV 집계 검증 및 그래프 생성 완료
- **Holdout:** 최종 결과 수신 및 검증 대기
- **Dashboard 연동:** 기존 Tuning CSV/JSON 구조 검토 완료, 최종 Holdout 데이터 계약 및 Benchmark Lab 읽기 연동은 미완료

기존 Evaluation 결과와 공개 Benchmark 기반 결과는 서로 다른 실험이므로 구분하여 제공한다. 검증되지 않은 지표는 0으로 대체하지 않는다.

### 6-2. 데이터 및 파일 구조

| 구분 | 파일 / 경로 | 용도 |
|---|---|---|
| Fatin 데이터 감사 | `audit_summary.json` | Tuning 집계 검증, 입력 해시, Dataset Manifest 및 검증 상태 |
| 재집계 결과 | `recomputed_sweep.csv` | B/C Threshold별 재집계 결과 |
| Guard 탐지 | `guard_detection.csv` | Dataset 및 Guard별 탐지 건수와 비율 |
| Core Latency | `core_latency.csv` | Security Core 지연 시간 집계 |
| 그래프 검증 정보 | `plot_audit.json` | Split, 입력 해시, 집계 결과 및 정상 send_email 실행 패턴 |
| 그래프 | PNG/SVG | B/C 공격 Tool 실행률, Direct/Indirect 비교, 정상 WARN/BLOCK, Latency |
| 별도 Benchmark Replay | `summary.json`, `summary.csv`, `trials.jsonl`, `trials.csv` | `contest-benchmark-v1` 형식의 독립 Mock Replay 실험 |

실제 저장 경로는 실행 시 지정한 `--output` 디렉터리에 따라 결정되며, 최종 Holdout 산출물 경로는 검증 후 확정한다.

### 6-3. Dashboard 데이터 계약

Fatin 데이터 감사 결과인 `audit_summary.json`은 `imported-fatin-audit-v1` 형식을 사용하며, 현재 상태는 `arithmetic_audited`, `evidence_validated=false`이다.

그래프용 `plot_audit.json`에는 `split`, `split_verification`, `toolpolicy`, `input_sha256`, `cells`, `benign_send_raw_patterns`가 포함된다.

별도 Benchmark Replay Exporter는 `contest-benchmark-v1` 형식을 사용하며, 완료된 결과에 대해 `read_benchmark_summary()` 검증을 지원한다.

현재 `demo/reports.py`는 기존 A/B/C Runtime Report 구조를 사용하고, `demo/workbench.py`의 Benchmark Lab은 데이터 연결 대기 상태이다. 따라서 Fatin 평가 결과와 Benchmark Replay 결과를 기존 Dashboard Report 형식으로 직접 대체하지 않는다.

### 6-4. 지표 및 표시 주의사항

- 공격 Tool 실행률과 실제 LLM Attack Success Rate(ASR)를 구분한다.
- 정상 WARN과 BLOCK을 구분하고, Tool 실행 전 차단과 실행 후 Output 차단을 별도 집계한다.
- 고유 Sample 수와 전체 Trial 수를 구분하고, 비율의 분자·분모를 함께 표시한다.
- Latency는 Security Core 단독 측정과 Runtime E2E 측정을 혼합하지 않는다.
- 실제 Agent/Jailbreak 파일럿은 별도 결과로 표시하며, 소규모 관측 결과를 일반적인 방어 성공률로 해석하지 않는다.
- 원본 모델 응답 및 재배포 조건이 확인되지 않은 데이터는 공개 Dashboard/포스터에 포함하지 않는다.

### 6-5. Holdout 수신 후 최종 인계

Holdout 결과 수신 후 다음 항목을 검증하고 최종 경로와 함께 지송님·지원님께 전달할 예정이다.

- Holdout 고유 Sample 수 및 Trial 수, 실패/제외 건수
- Security Core Commit, Policy/Threshold 및 Dataset Split/Hash
- B/C 최종 지표와 분자·분모, 공격 유형별 비교
- 최종 CSV/JSON 파일 경로 및 필드 구조
- 최종 PNG/SVG 그래프와 캡션, 실험 환경 및 한계
- 독립적인 Runtime Evidence 확인 가능 범위

**현재 상태:** Tuning 데이터 인계 준비 완료 / 최종 Holdout 데이터 및 Dashboard 통합 검증 대기

**최종 결론:** 이번 PR은 **Tuning 기반 Evaluation 구현, 집계 검증, 문서 및 그래프 생성 기능**을 검토받기 위한 것입니다. **최종 Holdout 성능 또는 Fatin의 당시 Runtime 실행을 독립 검증 완료했다고 주장하지 않습니다.**
