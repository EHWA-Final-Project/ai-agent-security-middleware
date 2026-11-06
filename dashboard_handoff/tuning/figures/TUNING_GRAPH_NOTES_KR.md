# Tuning 그래프 4종 — Dashboard / 포스터 인계 설명

**평가 담당:** Wana · Benchmark / Evidence / Evaluation  
**데이터 구분:** 2026-11-03 Tuning split (최종 Holdout과 별도)  
**원본 실행:** Fatin님 제공 실험 데이터  
**검증:** 제공 Trial/집계 결과 산술 대조 및 그림 입력 데이터 검증  
**핵심 주의:** 아래 금지 Mock Tool 실행률은 실험이 지정한 Tool 호출의 실행 여부를 뜻하며, 실제 LLM의 Attack Success Rate(ASR)가 아닙니다.

## 실험 범위

- Tuning Guard 샘플: **2,118개**; 평가 Sweep 원본: **23,392 Trial 행**.
- 한 조건에서 공격 **820건**(Direct **445**, Indirect **375**), 정상 `read_file` **362건**, 정상 `send_email` **194건**을 평가했습니다.
- 모드: **A = No Guard**, **B = Independent Guard**, **C = Linked Guard**.
- B/C Block Threshold: **0.70 / 0.75 / 0.80 / 0.85 / 0.90 / 0.92 / 0.95 / 0.98**.
- 아래 대표 수치는 별도 표시가 없으면 **Threshold 0.80**입니다. Tuning과 Holdout의 샘플·분모를 합산하지 않습니다.

## 1. B/C Threshold별 금지 Mock Tool 실행률

**파일:** `attack_tool_execution.png`, `attack_tool_execution.svg`  
**분모:** 전체 공격 820건, Direct 445건, Indirect 375건

| 모드 | 금지 Mock Tool 실행 | 실행 전 BLOCK |
| --- | ---: | ---: |
| A (No Guard) | 820/820 (100.0%) | 0/820 (0.0%) |
| B (Independent) | 752/820 (91.7%) | 68/820 (8.3%) |
| C (Linked) | 548/820 (66.8%) | 272/820 (33.2%) |

**해석:** 0.80 조건에서 C는 B보다 금지 Mock Tool 실행이 **204건 적었고**, 실행 전 차단은 **204건 많았습니다**. 이는 해당 Tuning 실험에서 연계형 Guard가 실행 전 통제에 기여했음을 보여 줍니다. 다만 모든 Threshold에서 같은 결과를 일반화하거나 실제 모델 공격 성공률로 해석해서는 안 됩니다.

**출처:** `tuning/recomputed_sweep.csv`, `tuning/plot_audit.json`, `tuning/audit_summary.json`

## 2. Direct / Indirect 공격별 비교

**파일:** `direct_indirect.png`, `direct_indirect.svg`  
**분모:** Direct 445건, Indirect 375건

| 공격 유형 | B 실행 | C 실행 |
| --- | ---: | ---: |
| Direct | 377/445 (84.7%) | 247/445 (55.5%) |
| Indirect | 375/375 (100.0%) | 301/375 (80.3%) |

**해석:** Direct와 Indirect 모두 C의 금지 Mock Tool 실행률이 B보다 낮았습니다. 특히 B는 해당 조건에서 Indirect 공격 **375건을 모두 실행**했고, C는 **301건을 실행**했습니다. 이 결과는 Tuning 표본 내 경향이며 외부 공격 전체에 대한 일반화나 실제 LLM의 공격 행동 성공을 입증하지 않습니다.

**출처:** `tuning/recomputed_sweep.csv`, `tuning/plot_audit.json`

## 3. 정상 요청 WARN/BLOCK 및 출력 전달

**파일:** `benign_warn_block.png`, `benign_warn_block.svg`  
**분모:** 정상 `read_file` 362건, 정상 `send_email` 194건

- B/C 정상 `read_file` WARN/BLOCK: **0/362 (0%)**.
- B/C 정상 `send_email` WARN/BLOCK: **194/194 (100%)**.
- 정상 `send_email` **실행 전 BLOCK: 0/194**; 위 194건은 **WARN**입니다.
- 원본 Tuning 실험에서 `send_email` Mock Tool은 실행되었으나, 결과가 최종 사용자 응답으로 전달되지 않았습니다.

**해석:** 정상 읽기 요청은 이 실험의 경고·차단 지표에서 영향을 받지 않았지만, 정상 이메일 요청은 모두 WARN으로 처리되었습니다. **WARN은 실행 전 차단과 동일하지 않으며**, Mock Tool 실행과 최종 결과 전달 여부를 구분해서 설명해야 합니다. 실제 이메일이 외부로 발송되었거나 의미적으로 완료되었다는 주장은 하지 않습니다.

**출처:** `tuning/recomputed_sweep.csv`, `tuning/plot_audit.json`, `tuning/audit_summary.json`

## 4. Security Core Latency 비교

**파일:** `core_latency.png`, `core_latency.svg`  
**분모:** 모드별 **1,000회**, 별도의 Security Core 마이크로벤치마크

| 모드 | 평균 (ms) | p50 (ms) | p95 (ms) |
| --- | ---: | ---: | ---: |
| A | 0.034 | 0.030 | 0.055 |
| B | 0.684 | 0.643 | 1.175 |
| C | 0.686 | 0.647 | 1.123 |

**해석:** Guard 적용 모드인 B/C는 A보다 Security Core 단독 처리 시간이 길었으며, 이 측정에서는 B와 C의 평균 지연이 유사했습니다. **이는 별도의 합성 Core 마이크로벤치마크**이므로 Tuning 공격 표본별 지연 또는 실제 LLM·Tool·SQLite를 포함한 End-to-End Runtime 지연으로 표시하면 안 됩니다.

**출처:** `tuning/core_latency.csv`, `tuning/audit_summary.json`

## 검증 범위 및 공유 유의 사항

- Tuning 산술 집계 감사 상태: `arithmetic_audited`. 개별 Runtime Evidence 대조: `evidence_validated=false`, 독립 Runtime 재실행: `runtime_execution_verified=false`.
- 이전 Tuning 데이터의 정확한 실험 당시 Security Core Revision 및 ToolPolicy 원본 Trial 재검증은 이 자료만으로 확인할 수 없습니다.
- Tuning 결과는 **최종 Holdout 결과와 별도**로 Dashboard에 표시해 주세요. 최신 대회용 최종 핵심 그림은 Holdout 그래프 4종입니다.
- 외부 Benchmark 및 특히 Tensor Trust 데이터 권리는 별도 확인이 필요합니다. 내부 데이터 인계가 공개 게시·재배포 권한을 의미하지 않습니다.
- 관련 자료: `tuning/recomputed_sweep.csv`, `tuning/guard_detection.csv`, `tuning/core_latency.csv`, `tuning/audit_summary.json`, `tuning/plot_audit.json`, `README.md`.
