# GuardOn 포스터 자산·시연 인계 — 2026-11-04

11/5 디자인 작업용 자료 준비다. 포스터 디자인·제출 PDF 완성이 아니다.

## 자산 목록

| 자산 | 상태 / 담당 | 캡션·범위 |
|---|---|---|
| `assets/poster/guardon_architecture.svg` | 소스 준비 / Jisong | 코드 기반 구조. Input/Context/Tool 실행 전, Output 실행 후. Mock Tool·SQLite Evidence |
| `assets/poster/guardon_plugin_registration.svg` | 소스 준비 / Jisong | GuardPlugin 구현·등록·활성화·검사·판정. 예제/계약 검증이며 운영 hot-swap이 아님 |
| Holdout 4종 PNG/SVG | 미수신 / Wana | `holdout_attack_tool_execution`, `holdout_benign_outcomes`, `holdout_tool_policy`, `holdout_c_block_causes` |
| Core Latency 그래프 | 원본 검증 자료 미수신 / Fatin | Security Core 단독. LLM/Tool/SQLite/Runtime E2E 제외 |
| 실측 Benchmark Lab | 미수신 자료 연결·브라우저 캡처 대기 / Jisong | Tuning·Holdout 구분, 분자/분모·출처·검증 범위 표시 |
| BENIGN/PRE-BLOCK/POST-OUTPUT-BLOCK | Runtime·UI 테스트 완료, 캡처 대기 / Jisong | 각각 Mock 호출 1/0/1, 출력 전달 true/false/false |
| Evidence/Registry/B/C | UI 구현·테스트, 캡처 대기 / Jisong | 저장된 run/trace와 현재 Registry 구분. B/C는 같은 합성 요청의 별도 실행 |

SVG는 1440×620 viewBox 벡터다. 고해상도로 확대할 수 있으나 브라우저 부재로 시각 검토하지 못했다. 최종 디자인에 넣기 전 글자 겹침·폰트·색 대비를 확인한다.

## 수치 사용 기준

현재 사용할 수 있는 자체 검증 사실: 최종 QA 문서의 테스트 pass/skip/fail, 실제 합성 시나리오의 판정·Mock 호출·출력 전달·run/trace 연결, health 200. 이는 보안 탐지 성능 수치가 아니다.

다음 수치는 문서 참고치다. 로컬 원본을 수신·대조하기 전 포스터의 자체 검증 측정치로 사용하지 않는다.

- Holdout 0.80: B pre-tool BLOCK 71/838, C 317/838. Mock Tool 실행 B 767/838, C 521/838. ToolPolicy 적용 시 0/838은 설정 효과다.
- 정상 read 337/338, Guard-only WARN 이상 1/456. 정상 send: default B 167/167 WARN, C 166 WARN + 1 BLOCK; Tool 실행/출력 전달을 구분해야 한다.
- C 0.80은 317건 모두 cumulative risk 기록이며 single_guard_ge_thr 71건은 중복 부분집합이다. 246건을 모든 threshold의 누적 원인으로 일반화하지 않는다.
- 합성 Security Core latency A 0.035ms, B 0.684ms, C 0.686ms는 별도 인계 기록이다. 전체 Runtime 지연으로 표현하지 않는다.

사용할 수 없는 주장: 실제 LLM ASR·semantic TSR·실제 이메일 전송 성공률·Holdout Runtime 독립 검증 완료·운영 Plugin hot-swap·미수신 그래프/캡처 완료·최종 통합 CI 통과. 실제 Ollama 파일럿은 이번에 재실행하지 않았으며 #28 보고의 관찰 사실과 자체 측정을 구분한다.

## 실행·1분 설명

작업 브랜치 워크트리에서:

```powershell
uv sync --frozen --group dev --group demo
uv run --group demo streamlit run demo/dashboard.py --server.address 127.0.0.1 --browser.gatherUsageStats false
uv run python examples/custom_guard.py
uv run --group demo pytest tests/contract/test_custom_guard_plugin.py -q
```

“GuardOn은 Guard 판단을 Runtime의 도구 실행과 출력 전달에 연결합니다. 정상 요청은 Mock Tool을 실행하고 결과를 전달합니다. 입력 공격은 Tool 호출 전에 차단합니다. 민감한 결과는 Tool이 실행된 후 출력 전달을 막습니다. 따라서 BLOCK이라고 해서 항상 Tool이 실행되지 않은 것은 아닙니다. B/C 비교는 같은 합성 요청을 독립 실행하고, Evidence는 각 run/trace로 확인합니다. Benchmark 수치는 실험이 지정한 Mock Tool intent에 대한 결과이며 실제 모델 공격 성공률과 구분합니다.”

## 3분 시연 동선

1. 0:00–0:40 정상 카드 실행: ALLOW / 호출 1 / 출력 전달 / Evidence 저장 확인.
2. 0:40–1:10 공격 카드: BLOCK / 호출 0. Guard 점수·규칙과 policy_version 확인.
3. 1:10–1:40 출력 카드: BLOCK / 호출 1 / 출력 차단. 실행을 되돌린 것으로 설명하지 않음.
4. 1:40–2:10 B/C 비교 expander: 같은 요청, 별도 run/trace·정책. 결과가 같은 것도 사실대로 표시. Replay는 저장 이벤트 재생이며 재실행이 아님.
5. 2:10–2:35 현재 Registry name/stage/enabled 및 Custom Guard 예제·계약 테스트 설명. 과거 정책 스냅샷과 혼동하지 않음.
6. 2:35–3:00 Benchmark Lab: 미수신 상태면 결과 없음 화면을 보여줌. 수신된 경우 threshold·분모·SHA·검증 범위를 설명. 실제 LLM ASR/semantic TSR은 unknown.

## 캡처·제출 점검 초안

- 캡처 fallback 파일은 아직 없다. 연결 가능한 브라우저에서 위 시나리오와 run/trace·현재 소스 commit SHA를 함께 기록한다.
- 장비 실행이 불가능하면 SVG 구조 설명과 실제 테스트 기록을 사용한다. 재현되지 않은 화면이나 수치는 생성하지 않는다.
- 화면 캡션에는 “합성 Mock Runtime”, 그래프에는 split·조건·threshold·분자/분모·측정 대상·SHA256·검증 범위를 적는다.
- Wana의 원본 그림 4종은 raw report/aggregate metadata와 대조하고, 라이선스·출처 표기를 동봉한다. 데이터 원문·모델 응답·로컬 DB는 전달/커밋 제외.
- 공개 URL/QR은 아직 확정되지 않았다. 비공개 GitHub/Notion URL을 심사위원용 접근 가능 QR로 제시하지 않는다. 로그아웃 상태에서 접근 검증한 공개 설명 페이지만 사용한다.
- 최종 PDF: 대회 규격·페이지 수·폰트 포함·벡터 선명도·명암 대비·QR 실물 스캔·캡션·분모·데이터 권리·비밀정보 유무 확인. 현재는 체크리스트 초안이며 확인 완료 표기가 아니다.
