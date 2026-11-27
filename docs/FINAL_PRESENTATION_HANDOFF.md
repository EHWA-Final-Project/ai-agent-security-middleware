# 최종 발표 인계

흰 배경, 검정 글씨, 간결한 표·그래프를 사용한다. 슬라이드 하단에 범위·분모·출처를 적는다. 이번 인계는 발표 원고와 실제 그래프이며 별도 PPT/MP4 파일 제작을 완료했다고 주장하지 않는다.

## 권장 7장 구성

| 장 | 제목 / 핵심 문장 | 사용할 근거 |
|---|---|---|
| 1 | GuardOn: Agent의 실행과 출력 전달을 별도로 통제한다 | `FINAL_ARCHITECTURE_AND_RESULTS.md` 구조도 |
| 2 | Input/Context/Tool/Output + A/B/C/D, D는 필수 검사와 ToolPolicy 유지 | `src/security/policy/condition_configs/`, `tests/unit/test_extended_injection_rules.py` |
| 3 | 실제 Qwen3:8b가 두 문서를 읽는 다단계 실행; 선택/SDK/서버/모델 전달을 분리 관측 | Runtime Replay `abcd_multistep/C` 및 D |
| 4 | 실행 전 BLOCK(0회)과 실행 후 통제(1회)를 구분한다 | Runtime `abc_normal_preblock`, `abc_postblock`; Candidate SDK/server count |
| 5 | 외부 변환 표본 12개, A/B/C/D 단일 반복 48시도 | `reports/external_mcp_actual/dashboard/graphs/execution_status.png` |
| 6 | 실제 관측 지표와 N/A를 함께 보여준다 | `operational_boundaries.png`, `unauthorized_tool_observations.png`, `generated_response_findings.png` |
| 7 | Evidence Replay와 최종 QA, 새 실모델·육안 QA 미수행 범위를 공개한다 | `FINAL_INTEGRATION_QA.md`, Freeze tag |

## 발표에 바로 사용할 수치

| 문구 | 값 / 정확한 범위 | 근거 파일 |
|---|---|---|
| 실제 외부 평가 시도 | 48, 12표본 × 4조건 | `experiment_configuration.json` |
| 실행 상태 | 완료 41 / Timeout 5 / 오류 2 | `dashboard/trial_observations.json` |
| 정상 요청 완료 | 24/24; 과제 정답률 아님 | 같은 표 |
| 네 조건 모두 완료 | 9/12표본 | `dashboard/matched_abcd_comparisons.json` |
| 완료 Trial의 Candidate 실행 | 42/46 | `dashboard/operational_metrics.json`, scope=completed_trials_primary |
| 실행 전 차단 | 4/46 Candidate; ToolPolicy 적용 결과 | 같은 표 |
| 실행된 출력의 모델 전달 | 40/42 Candidate; 사용자 전달 아님 | 같은 표 |
| 실행 후 출력 미전달 | 2/42 Candidate; 개별 Output Guard BLOCK과 다름 | 같은 표 |
| BIPIA 공격 Payload 모델 전달 | 완료 공격 15/15 Trial | 같은 표 |
| 공식 ASR / TSR / FPR | N/A | `dashboard/report_summary_ko.json`의 공식지표 |

위 경로의 기준 디렉터리는 `reports/external_mcp_actual/`이다. 표본 출처·라이선스·변환 hash는 `benchmarks/mcp_external_manifest.json`을 사용한다.

## 그래프와 Latency

`reports/external_mcp_actual/dashboard/graphs/`에 상태·경계·비인가 Tool·생성 응답 분석 PNG/SVG 4종이 있다. 다섯 번째는 `reports/external_mcp_actual/latency/backend_latency.png`이며 집계 CSV와 provenance JSON이 함께 있다. Dashboard에서 원본 파일을 로딩한다.

완료 Trial Backend mean(s): A 275.27 / B 314.55 / C 263.18 / D 328.68. LLM 포함, Timeout/오류 제외, 조건별 완료 표본 다름. D의 속도 우위나 Guard overhead로 해석하지 않는다. 별도 Security Core 실험의 약 31.5% 감소는 긴 출력의 Core 단독 처리 시간으로만 설명하고 이번 최종 SHA의 새 측정으로 제시하지 않는다.

확장 규칙의 과거 탐지 실험은 #47 인계 및 `GuardOn_AdaptiveD_Reproducibility.zip`의 별도 결과다. 실제 48시도의 PI-T01 ON과 확장 규칙 실험을 혼합하지 않는다. 확장 규칙은 기본 OFF이며 탐지는 WARN까지일 수 있다. 최종 실행 로그의 정확한 policy_version을 함께 제시한다.

## 질문 대응 문장

- “차단 4건은 비인가 Tool에 대한 ToolPolicy 결과이며 Injection 탐지 성공률이 아닙니다.”
- “완료 41건은 실행 완료입니다. 최종 사용자 전달과 정답을 모두 증명한 수가 아닙니다.”
- “알 수 없음은 0이 아닙니다. 근거 부족 지표는 N/A로 유지했습니다.”
- “이 화면은 저장된 실제 실행 기록입니다. 새 실시간 실행과 분리했습니다.”
- “Runtime 기능 검증 45건(29 Agent + 16 고정 후보)은 외부 Benchmark 48시도와 별도입니다.”

최종 QA count와 dev SHA는 최종 gate 결과와 `git rev-parse guardon-freeze-20261127`에서 옮겨 적는다. 새 실모델 실행·육안 QA·녹화가 완료되기 전에는 해당 검증을 완료로 발표하지 않는다.
