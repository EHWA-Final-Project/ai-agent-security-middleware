# Agent Security Workbench · 포스터 원고 초안

2026-11-01 · 오지송 / 이지원 공동 편집용. PDF/PPT 완성본 또는 공식 제출본이 아니다.
근거: dev `75889b3`, 현재 코드 및 [팀 실행 기준서](https://app.notion.com/p/404800434d53819bb1d6e370bc9a9e67)의 7·8·10·14절.

## 1. 연구 배경
AI Agent는 문서 조회와 도구 호출을 통해 사용자 요청을 실제 작업으로 전환한다. 사용자 입력과 외부 문서의 Prompt Injection은 비신뢰 지시를 실행 권한으로 승격시킬 수 있다. Jailbreak 탐지와 함께 실제 도구 호출 및 출력 전달 경계의 통제가 필요하다.

## 2. 문제 정의
단일 Guard 판단은 서로 다른 단계에서 누적되는 실행 위험을 놓칠 수 있다. 실행 전 차단은 도구 호출을 막지만, 실행 후 출력 차단은 이미 발생한 도구 효과를 되돌리지 못한다. 보안 강화의 이점은 정상 작업 성공률, 오탐 및 지연 비용과 함께 평가해야 한다.

## 3. 연구 목표
Input·Context·Tool·Output의 플러그인 기반 4단계 Guard를 구성한다. SecurityContext에 판단 정보를 축적하고 Cross-layer Coordination으로 연계한다. Runtime Enforcement가 실행 경계에서 결정을 집행하며, SQLite Evidence로 판단과 실행 결과를 추적·재생한다.

## 4. 핵심 차별점
- B Independent와 C Linked의 동일 조건 비교로 연계 효과를 검증한다.
- Tool 실행 이전의 권한 집행과 실행 이후 출력 보호를 분리한다.
- Guard 근거·위험 점수·지연과 실행 결과를 run_id/trace_id로 연결한다.
- 공개 Benchmark를 통한 객관적 평가를 계획하고, 합성 Mock 시연과 구분한다.
- Developer Workbench에서 실행 → 결과 → Replay → Evidence를 확인한다.

## 5. 현재 구현 아키텍처
실선으로 제안할 구현 연결: Streamlit → demo/service.py → RuntimeAdapter → Security Orchestrator / PluginManager → Guard Plugins / SecurityContext → SecurityDecision → Enforcement. Tool 실행 이후 Output Guard 검사가 가능하다. EvidenceCollector → SQLite → Replay 및 Evaluation Report 조회 경로를 별도로 배치한다. 이 연결도는 이벤트 시간 순서를 대신하지 않는다.

현재 도구는 MockReadFile / MockSendEmail이며 실제 파일 삭제·메일 발송은 없다. 실제 LLM Agent, FastAPI, Docker, AWS 및 공개 웹 배포는 이 브랜치에서 구현·배포 완료로 표시하지 않는다. FastAPI PR #14는 미병합이다.

## 6. 실험 설계 초안
A No Guard는 실험 전용, B Independent와 C Linked는 동일 Guard·정책·입력·Tool 조건에서 비교한다. 기존 0.80/0.92 합성 Fixture 보고서는 보존하며 공개 Benchmark 성능으로 일반화하지 않는다. 0.92는 메커니즘 시연점이다.

공개 공격·정상 데이터 후보는 BIPIA, Tensor Trust, JailbreakBench, NotInject다. 실제 사용 subset·버전·라이선스·split·seed·고유 표본 수는 Wana 확정 후 기입한다. 다중 Threshold 및 동일 FPR 비교를 계획한다.

| 지표 | 기입 기준 |
| --- | --- |
| ASR | 공격 성공 trial / 평가 가능한 공격 trial. 금지 Tool 실행·출력 유출·실제 LLM Jailbreak 성공 기준을 분리 |
| TSR | 정상 작업 성공 trial / 정상 trial |
| FPR | 정상 요청 오차단 trial / 정상 trial; WARN 처리 기준은 담당자 확인 |
| Block Rate | 차단 trial / 전체 trial; 실행 전·출력 차단 분리 |
| Latency | 동일 환경·측정 범위의 mean/p50/p95, 단위 ms |

위 정의는 원고용이며 공식 평가 계약·산식을 변경하지 않는다. 실패 trial 처리 및 분모는 최종 exporter와 대조한다.

[결과 그림 자리: Threshold별 ASR/FPR/TSR 및 B/C 지연 비교 — 실측 수령 전 공란]

## 7. 결과·논의·한계 — 자료 수령 대기
정량 결과와 우위 주장은 비워둔다. Wana에게 원본 CSV/JSON, dataset manifest, 고유 공격/정상 n, 총 trial, Threshold, 환경·측정 범위, 실패 제외 기준, 그래프와 축·단위·분모 캡션을 받는다. Fatin에게 실제 Agent 모델/버전, 공격별 성공 기준, 알려진 미탐, 대표 SecurityResult 및 run/trace를 받는다.

[결과 표 공란] [논의 공란] [최종 한계 공란]

후속 검토 항목: 고정 규칙의 일반화, 중복 위험 신호 누적, 오탐·지연 Trade-off, Mock와 실제 Agent 차이. 최종 근거가 있는 항목만 결과 설명에 반영한다.
