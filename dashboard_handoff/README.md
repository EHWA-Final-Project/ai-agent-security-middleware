# Evaluation Dashboard 자료 인계 안내 (2026-11-04)

## 1. 자료 개요

이 ZIP은 **팀 내부 Benchmark Lab/Dashboard 연동과 11/6 경진대회 포스터 준비**를 위해 정리한 Evaluation 결과물입니다. Tuning과 Holdout의 집계 데이터, 검증 보고서, PNG/SVG 그래프 원본을 포함합니다.

**중요한 확인 사항**
- **Tensor Trust 데이터의 재배포 및 결과 공유 권한은 아직 명확히 확인되지 않았습니다.** 팀 내부 자료라고 해서 자동으로 공유·공개 권한이 생기는 것은 아닙니다. 외부 공개 또는 포스터에 수치를 게시하기 전 데이터 이용 범위를 별도로 확인해야 합니다.
- 이 자료는 **제공받은 실험 결과의 산술적 일치 여부를 검증한 것**입니다. `runtime_execution_verified: false`이며, 원래 Runtime 실행을 독립적으로 재실행하거나 개별 Evidence 기록을 대조한 결과는 아닙니다.
- 문서와 그래프의 **금지 Mock Tool 실행률**은 실험에서 미리 제공한 호출의 실행 비율이며, 실제 LLM 공격 성공률(ASR)을 의미하지 않습니다.

## 2. 실험 범위

| 구분 | Guard 고유 샘플 | Sweep Trial 행 | 조건별 공격 / 정상 읽기 / 정상 이메일 |
| --- | ---: | ---: | --- |
| Tuning (Default) | 2,118 | 23,392 | 820 / 362 / 194 |
| Holdout (Default) | 1,294 | 22,831 | 838 / 338 / 167 |
| Holdout (ToolPolicy 적용) | 동일 Holdout 샘플 | 22,831 | 838 / 338 / 167 |

각 Sweep은 **17개 조건**(A: No Guard 1개, B/C: Threshold 8개씩)을 비교합니다. Threshold는 `0.70, 0.75, 0.80, 0.85, 0.90, 0.92, 0.95, 0.98`이며, 대표 비교값은 **0.80**입니다.

- Tuning 공격 820건: Direct 445건, Indirect 375건
- Holdout 공격 838건: Direct 463건, Indirect 375건
- Holdout 정상 Guard 샘플 456개. Sweep에서 정상 `read_file` 338건과 `send_email` 167건을 평가합니다.
- 동일 샘플을 여러 Threshold에서 반복 평가했으므로 **Trial 행 수를 서로 독립적인 샘플 수로 해석하지 않습니다.**
- Tuning과 Holdout, 과거 별도의 소규모 Replay(35개 샘플/1,120 Trial)는 서로 합산하지 않습니다.
- Holdout Guard 샘플 1,294개와 Sweep에서 사용한 고유 ID 1,176개는 서로 다른 집계 범위입니다. 질문형 Guard-only 샘플 118개는 Sweep에 포함되지 않았으며, 일부 정상 ID는 읽기/이메일 시나리오에서 재사용되었습니다.

## 3. 폴더 및 파일 안내

### Holdout (`holdout/`)

| 파일 | 내용 |
| --- | --- |
| `holdout_results.json` | Holdout 주요 집계 결과 및 Dashboard 연동용 값 |
| `sweep_holdout_summary.csv` | Default A/B/C Threshold별 집계 |
| `sweep_policy_holdout_summary.csv` | ToolPolicy 적용 A/B/C 집계 |
| `c_cause_holdout.csv` | C 모드의 실행 전 차단 원인 집계 |
| `raw_verification.json` | 원본 Trial 재집계와 Summary 대조 결과를 기록한 검토본 |
| `run_record_holdout.json` | 실험 조건·출처·해시 정보가 포함된 검토본 |
| `figures/` | 최종 Holdout 그래프 4종, 각각 PNG/SVG |
| `figures/aggregate_validation.json` | 그래프/검증 패키지 검증 정보 |

### Tuning (`tuning/`)

| 파일 | 내용 |
| --- | --- |
| `audit_summary.json` | Tuning 검증 결과 및 한계 |
| `plot_audit.json` | 그래프 수치와 감사 결과 대조 |
| `recomputed_sweep.csv` | 검증된 Tuning Default Sweep 집계 |
| `guard_detection.csv` | Guard 탐지 관련 집계 |
| `core_latency.csv` | Security Core 단독 Latency 측정 결과 |
| `figures/` | Tuning 그래프 4종, 각각 PNG/SVG |

Holdout 그래프: `holdout_attack_tool_execution`, `holdout_benign_outcomes`, `holdout_c_block_causes`, `holdout_tool_policy`

Tuning 그래프: `attack_tool_execution`, `benign_warn_block`, `core_latency`, `direct_indirect`

### 검증/패키징 메타데이터 (ZIP 최상위)

- `PACKAGE_MANIFEST.json`: 원본과 공유용 검토본의 관계, 제외·변환 내역, 파일 목록
- `SHA256SUMS.txt`: 패키지에 포함된 다른 파일의 SHA256 체크섬
- `package_review.json`: 패키징 및 포함 파일 점검 결과 (새로운 실험 검증 결과는 아님)

## 4. Dashboard에서 결과를 사용할 때

**Holdout:** `holdout/holdout_results.json`과 관련 집계 CSV를 사용하고, 수치 대조 근거는 `holdout/raw_verification.json`을 참고합니다.

**Tuning:** `tuning/recomputed_sweep.csv` 또는 `tuning/audit_summary.json`을 사용하며, 그래프 수치 대조 근거는 `tuning/plot_audit.json`을 참고합니다.

**지표 해석 시 주의사항**
- 기존 결과에서 `ASR`로 표기된 값은 **실험이 지정한 금지 Mock Tool 실행률**입니다. 실제 LLM 기반 공격 성공률로 표현하지 않습니다.
- `TSR_read`는 **Tool 실행과 결과 전달이 모두 이루어진 비율**이며, 작업을 의미적으로 정확하게 수행했다는 뜻은 아닙니다.
- WARN으로 결과 전달이 보류된 경우와 실행 전 BLOCK, 실행 후 Output BLOCK을 구분합니다. 실제 이메일 발송 여부는 측정하지 않았습니다.
- ToolPolicy로 금지 호출을 막은 것은 **명시적 권한 정책의 효과**이지 Guard 탐지율이 100%라는 뜻이 아닙니다.
- 실제 모델 기반 ASR, 의미적 TSR, 전체 End-to-End Latency는 확인된 값이 없으므로 임의로 채우지 않습니다.
- Tuning의 `core_latency` 그래프는 **별도 Security Core 마이크로벤치마크**입니다. Runtime/LLM/Tool/SQLite를 포함한 전체 지연 시간으로 설명하지 않습니다.

## 5. 검증 범위 및 남아 있는 한계

**Holdout**
- 원본 Trial 재집계 결과는 `raw_arithmetic_verified`입니다. 제공된 Summary/차단 원인/Guard 메타데이터와의 산술적 불일치가 없었습니다.
- 패키징 과정에서 원본 CSV의 SHA256 일치를 확인했지만, **그 단계에서 원래 실험을 재실행하거나 원본 Trial 전체를 새로 평가한 것은 아닙니다.**
- 최종 Holdout PNG/SVG 4종은 Raw 산술 검증을 거친 그림 세트에서 원본 그대로 복사했습니다.

**Tuning**
- 집계 결과는 `arithmetic_audited`이나 독립 Evidence 검증은 완료되지 않았습니다(`evidence_validated=false`).
- `plot_audit.json`의 수치가 검토된 Tuning 집계와 일치합니다. 그래프는 당시 Tuning v2 버전으로 **잠정 결과**입니다.
- 당시 정확한 Security Core/설정 버전과 ToolPolicy의 원본 Trial 독립 검증은 확인되지 않았습니다.
- 과거 Trial에는 Split 필드가 없어 Tuning 구분은 호출자가 지정한 구분을 따릅니다.

**공통**
- 개별 Trial에 `run_id` / `trace_id`가 없으므로 SQLite Evidence와 일대일 대조하지 못했습니다.
- 해시가 일치한다는 것은 파일 일관성을 뜻하며, 원래 Runtime 실행의 진위나 Holdout 분할·Freeze 시점의 독립 증명은 아닙니다.
- Holdout은 제공된 단일 실험 결과로, 신뢰구간을 계산한 자료는 아닙니다.
- 일부 실제 Agent/Jailbreak 파일럿 집계가 Tuning 감사 자료에 남아 있지만, 전체 판정이 독립 검증된 벤치마크 수치는 아니므로 별도로 취급합니다.

## 6. 출처 및 데이터 공유 범위

- **BIPIA:** [원본 라이선스](https://github.com/microsoft/BIPIA/blob/a004b69ec0dd446e0afd461d98cb5e96e120a5d0/LICENSE). 일부 table/code context는 CC BY-SA 등 별도 조건이 적용됩니다.
- **Tensor Trust 데이터:** [별도 데이터 저장소](https://github.com/HumanCompatibleAI/tensor-trust-data), [라이선스 문의](https://github.com/HumanCompatibleAI/tensor-trust-data/issues/3). **공유 권한 미확인**. 코드 저장소의 BSD 라이선스가 별도 데이터셋까지 허용한다는 뜻은 아닙니다.
- **NotInject:** [데이터셋 카드](https://huggingface.co/datasets/leolee99/NotInject/blob/main/README.md). MIT 표기와 필요한 고지 조건을 확인해야 합니다.
- **JailbreakBench / JBB-Behaviors:** [라이선스](https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors/blob/main/LICENSE). 이 Tuning/Holdout Sweep에는 포함되지 않은 별도 파일럿 자료입니다.

위 라이선스 설명은 **2026-11-04 조사 기준**입니다. 원본 텍스트가 없더라도, Tensor Trust 결과를 포함한 혼합 집계 수치의 외부 공개 권한까지 확정된 것은 아닙니다. 실제 공개·재배포 가능 범위는 별도 확인이 필요합니다.

## 7. 원본 ZIP 대신 검토본을 넣은 이유

Fatin님이 전달한 **`for-wana.zip` 원본은 이 패키지 안에 다시 넣지 않았습니다.** 필요한 파일을 풀어서 공유 범위를 검토한 후 다음처럼 구성했습니다.

- 원본 ZIP의 **집계 CSV 3개는 파일 내용을 변경하지 않고 포함**했습니다.
- `holdout_results.json`과 `run_record_holdout.json`은 **개인 로컬 경로·불필요한 식별 정보 등을 정리한 검토본**으로 포함했습니다.
- `HOLDOUT_DATA_GUIDE.md`의 설명은 이 README에서 함께 안내합니다.
- 검증 보고서에 남은 일부 개별 샘플 ID나 개인 경로를 제거했으며, **수치·분모·해시 및 검증 한계는 유지**했습니다.
- 원본과 검토본의 해시는 다릅니다. 변환/제외 내용과 원본 파일 관계는 `PACKAGE_MANIFEST.json`에 기록했습니다.

**이번 패키지에서 제외한 자료:** Holdout Trial CSV 3개(`guards_holdout.csv`, `sweep_holdout_trials.csv`, `sweep_policy_holdout_trials.csv`), Tuning의 개별 샘플/Trial CSV, 원본 Benchmark 텍스트·Prompt·모델 응답·Trace·Evidence DB 및 중복된 이전 그래프.

따라서 이 ZIP은 **Dashboard 연결을 위한 검토된 집계·검증·그래프 자료**이지, 모든 원본을 포함한 독립 실험 재현 패키지는 아닙니다. 외부 공개 허가를 증명하는 자료도 아닙니다.
