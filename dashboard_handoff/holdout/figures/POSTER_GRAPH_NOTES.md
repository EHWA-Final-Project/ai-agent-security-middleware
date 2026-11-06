
# Holdout 최종 그래프 — 포스터용 설명

**담당:** Wana · Benchmark / Evidence / Evaluation  
**기준:** 2026-11-04 Holdout 검증 결과  
**실험:** Fatin님의 Security Core Holdout 실행 결과  
**검증:** 제공된 원본 Trial CSV 재집계 및 그래프 검증

## 1. B/C Threshold별 금지 Tool 실행률

**파일:** `holdout_attack_tool_execution.png` / `.svg`

**분모:** 공격 838건 (Direct 463건, Indirect 375건)

**Threshold 0.80 결과**
- A (No Guard): 838/838 (100%)
- B (Independent): 767/838 (91.5%)
- C (Linked): 521/838 (62.2%)
- 실행 전 BLOCK: B 71/838 (8.5%), C 317/838 (37.8%)

**해석:** C(Linked) 모드는 B(Independent)보다 금지 Mock Tool 실행률이 낮았으며, Threshold 0.80 기준 실행 전 차단 건수가 71건에서 317건으로 증가했습니다. 이는 Guard 연계 방식이 해당 실험 조건에서 실행 전 보안 통제를 강화할 수 있음을 보여줍니다. 다만 실제 LLM 기반 공격 성공률(ASR)을 측정한 결과는 아닙니다.s

**출처:** `sweep_holdout_summary.csv`, `holdout_results.json`

## 2. 정상 작업 영향

**파일:** `holdout_benign_outcomes.png` / `.svg`

**분모:** 정상 read_file 338건, send_email 167건

**Threshold 0.80 결과**
- B/C 정상 read_file 완료: 337/338 (99.7%)
- Default 정상 send_email WARN/BLOCK: 167/167 (100%)
- ToolPolicy 적용 시 정상 send_email WARN/BLOCK: 1/167 (0.6%)

**해석:** 정상 파일 읽기 작업은 B/C 모두 99.7% 완료되어 높은 정상 작업 유지율을 보였습니다. 반면 Default 설정에서는 정상 이메일 요청에도 WARN/BLOCK이 발생하여 보안 정책이 정상 작업에 영향을 줄 수 있음을 확인했습니다. 따라서 공격 차단 성능뿐 아니라 정상 요청에 대한 영향도 함께 고려해야 합니다.

**출처:** `sweep_holdout_summary.csv`, `sweep_policy_holdout_summary.csv`

## 3. ToolPolicy 적용 결과

**파일:** `holdout_tool_policy.png` / `.svg`

**분모:** 공격 838건

**Threshold 0.80 결과**
- B/C 금지 Mock Tool 실행: 0/838 (0%)
- B/C 실행 전 BLOCK: 838/838 (100%)

**해석:** 명시적 ToolPolicy 적용 시 B/C 모두 금지 Mock Tool 호출 838건을 실행 전에 차단했습니다. 이는 Guard 판단과 별개로 Tool 권한 정책이 실제 실행 단계에서 보안 통제 역할을 수행할 수 있음을 보여줍니다. 단, 정책에 따른 차단 결과를 Guard 자체의 공격 탐지 정확도로 해석해서는 안 됩니다.

**출처:** `sweep_policy_holdout_summary.csv`, `holdout_results.json`

## 4. C 모드 차단 원인 분석

**파일:** `holdout_c_block_causes.png` / `.svg`

**분모:** 공격 838건, Threshold 0.80에서 C 실행 전 차단 317건

**Threshold 0.80 결과**
- C 실행 전 BLOCK: 317/838 (37.8%)
- Cumulative Risk로 기록된 차단: 317건
- Single Guard Threshold 충족: 71건 (317건에 포함된 중복 부분집합)

**해석:** Threshold 0.80에서 C 모드의 실행 전 차단 317건은 누적 위험도(Cumulative Risk) 기준으로 기록되었습니다. 이 중 71건은 단일 Guard 기준으로도 차단 가능한 사례와 겹치므로, 모든 차단을 Guard 연계만의 추가 효과로 해석할 수는 없습니다. 이는 연계형 보안 판단의 기여와 함께 중복 위험 신호의 영향을 고려해야 함을 보여줍니다.

**출처:** `c_cause_holdout.csv`, `holdout_results.json`

## 검증 범위 및 주의 사항

- Holdout Default와 ToolPolicy 각각 22,831 Trial 재집계
- Summary 34개 조건 및 C 차단 원인 8개 조건 불일치 0건
- 원본 Trial 산술 검증 완료 (`raw_arithmetic_verified`)
- 실제 Security Core/Runtime 독립 재실행 및 개별 Evidence 대조는 포함되지 않음
- 금지 Mock Tool 실행률은 실제 모델 공격 성공률(ASR)과 구분

**관련 자료**
- Evaluation PR #26
- Benchmark / Evidence / Evaluation Notion
- Fatin님의 Holdout Summary `for-wana.zip`
