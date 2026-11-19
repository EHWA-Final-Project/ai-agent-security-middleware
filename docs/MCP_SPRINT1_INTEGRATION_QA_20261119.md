# GuardOn Sprint 1 통합 QA — 2026-11-19 (KST)

## 판정: BLOCKED / dev 병합 보류

필수 실서버 Output sanitize 조건이 실패했다. 비밀정보는 전달되지 않지만,
요청된 ‘마스킹 후 전달’과 현재 ‘실행 후 출력 BLOCK’은 다르다.
핵심 보안 로직/threshold는 임의로 바꾸지 않았다. 세 원본 PR은 모두 Open이며
dev 병합 및 병합 후 최신 dev 최종 QA는 수행하지 않았다.

## 검토 기준과 통합

- 원격 dev: `65052a4767219352a6e27e3e3d6dee7516f8cac5` (종료 전 원격 재조회 동일)
- #37 Security: `c40cb67051a012f487e947f9c4a75c52dde254ba`
- #38 Runtime: `c53e5b9e7b09bb1e7d0b8b22b2de9bf7a7f7f24a`
- #36 Evaluation: `956d8c9c0dc36fd983814b24b8d459208c6b64fe`
- 조회 시 모두 dev 대상 Open, MERGEABLE, statusCheckRollup 비어 있음.
- 임시 브랜치: `qa/mcp-sprint1-20261119`
- worktree: `.worktrees/mcp-sprint1-20261119`
- 적용 순서 #37 → #38 → #36, 충돌 없음.
- 세 PR 통합 커밋: `14f2c9fa054299e24a87f80ea0b7b1ad2f30d32e`
- 원래 checkout의 dev와 미추적 `.worktrees/`, 중첩 저장소 보존. main/#14 미변경.

## PR별 리뷰

### #37 Security

민감 Tool 분류에는 base 이름, allowlist에는 전체 qualified 이름을 사용한다.
정책 없는 qualified Tool은 명시 BLOCK. 기존 bare 이름 계약과 DTO는 유지된다.
OutputGuard는 qualified read_file의 content를 검사하고 sanitize 메서드도 구현한다.
그러나 sanitize 메서드 단위 테스트 성공은 Orchestrator 경유 성공을 뜻하지 않는다.
`is_qualified`는 슬래시 유무만 판별하며 이름 형식 검증은 후속 범위다.

### #38 Runtime

실제 SDK ClientSession의 list_tools/call_tool 및 BlockingPortal을 통해 동기 Runtime과
비동기 stdio Client를 연결한다. SDK는 lockfile의 mcp/mcp-types 2.3.0으로 설치됐다.
Demo Server의 read_file은 resolve/is_relative_to로 root 밖 접근을 거부하며
send_email은 외부 통신 없는 시뮬레이션이다. 기본 root는 저장소 tests 디렉터리다.
ToolPolicy 주입은 make_condition_security_factory(..., tool_policy=...)로 가능하다.
runtime.composition.make_security_factory 기본값은 정책 없는 ToolGuard이므로 qualified
Tool을 기본 차단한다. 실제 MCP 사용 시 허용 정책을 명시한 조립 경로가 필요하다.

원본 Ruff 오류 9건: import 정렬 3건, nested async with 6건.
임시 브랜치에서 import 정렬과 동등한 다중 context 문법으로 수정했다.
MCP Error/Timeout/Fallback 전용 검증은 미수행이다.

### #36 Evaluation

공격/정상 6쌍, 총 12개 합성 specification_only 시나리오와 엄격한 Manifest 검증이다.
실행 전 차단과 실행 후 출력 차단을 별도로 분류하며 timeout/호출 0회만으로
방어 성공이라고 판단하지 않는다. 실제 모델 ASR 측정 결과는 없다.
fixture-mcp는 메모리 매핑, demo는 실제 sandbox 파일을 사용한다.
fixture의 send_email.to는 목록을 허용하는 규약이고 demo SDK 함수는 문자열이므로
Sprint 2 실행 시 명시 매핑이 필요하다. read_file(path), subject/body 이름은 대응한다.

## 실제 실행 환경과 명령

Windows PowerShell, uv, CPython 3.12.13, 격리 worktree의 새 .venv.

```powershell
uv sync --frozen --group dev --group demo
uv run --frozen --group demo pytest -q tests/integration/test_mcp_enforcement.py tests/integration/test_mcp_name_policy_runtime.py tests/unit/test_mcp_scenarios.py
uv run --frozen --group demo ruff check .
uv run --frozen --group demo pytest -q
.venv\Scripts\ruff.exe check --fix src/runtime/mcp/executor.py src/runtime/mcp/host_adapter.py tests/integration/test_mcp_enforcement.py tests/integration/test_mcp_sprint1_cross_boundary.py
.venv\Scripts\python.exe -m pytest -q -s tests/integration/test_mcp_sprint1_cross_boundary.py
.venv\Scripts\python.exe -m pytest -q --tb=short
.venv\Scripts\ruff.exe check .
git diff --check
```

uv 캐시/네트워크 및 MCP 자식 프로세스 실행에는 환경 권한 확장을 사용했다.
설치 후 직접 .venv 실행은 동일 Python/패키지를 사용한다.

## 실행 결과

- 의존성 frozen sync: 성공.
- 원본 focused 3개 파일: **67 passed**, failed/skipped 0.
- 원본 세 PR 전체: **723 passed**, failed/skipped 0, 66.13초.
- 원본 Ruff: **9 errors**.
- 신규 교차 테스트 초기 실행: **1 passed, 1 failed**, skipped 0.
- 스타일 수정 후 Ruff: **All checks passed**.
- git diff --check: 통과.
- 최종 전체 실행: **724 passed, 1 failed, 0 skipped**, 51.91초.
  실패: test_real_mcp_cross_boundary[C]의 secret 마스킹 ALLOW 조건.
  기존 723개 회귀는 모두 통과했다. 통합 완료로 해석하지 않는다.

## 실제 MCP 경계별 관측

신규 test_mcp_sprint1_cross_boundary.py는 임시 파일 root의 실제 Demo Server를 띄운다.
ClientSession.call_tool 직전에 횟수를 세며 성공 출력/실행 상태도 함께 확인한다.
서버 내부 counter를 별도 RPC로 조회한 것은 아니다. 0회는 전송 함수 미호출,
1회 정상은 실제 응답 및 executed=true로 확인한다.

| 호출 후보 (B/C 각각) | tools/call | 결과 |
| --- | --- | --- |
| demo/read_file, docs/clean.txt | 1 | ALLOW, content 전달 |
| evil/read_file (실제로 등록한 alias) | 0 | BLOCK, executed=false |
| demo/read_file, 정책 없음 | 0 | BLOCK, executed=false |
| 허용 범위 밖 private.txt | 0 | BLOCK, executed=false |
| docs/../private.txt | 0 | BLOCK, executed=false |
| demo/send_email, a@corp.com | 1 | ALLOW, 시뮬레이션 응답 |
| demo/send_email, a@evil.invalid | 0 | BLOCK, executed=false |
| demo/read_file, API_KEY 가짜 응답 | 1 | B/C 모두 실행 후 출력 BLOCK |

B 전체 8개 후보와 C secret 직전 7개 후보에서 SQLite SECURITY_DECISION과
EXECUTION_RESULT 각 1건, run_id/trace_id 일치, decision/executed/tool_call_id 일치를 확인했다.
C secret은 마스킹 ALLOW assertion에서 중단되어 해당 후보의 SQLite assertion은 미도달이다.
출력 허용 여부는 Runtime 결과에서 확인했다. DTO에 없는 output_allowed를 SQLite에
기록했다고 주장하지 않는다. 원시 ExecutionResult/Evidence에는 가짜 secret이 남는다.

## 필수 수정 요청 (발송하지 않은 전달용 내용)

Fatin / Security Core와 Runtime 담당자 협의 필요:

1. 기본 C 정책에서 실제 read_file 결과 `API_KEY=sk-fake-sprint1`은 위험 0.95로
   block_threshold 0.80을 넘어 Orchestrator._run_stage에서 즉시 BLOCK된다.
2. _handle_warn의 sanitize는 STRICT+WARN OUTPUT에서만 호출되며 위 조건은 먼저 반환된다.
   따라서 이름 호환/select_output 분기만으로 실경로 redaction 전달을 달성할 수 없다.
3. 보안 정책상 출력 BLOCK이 의도인지, 명세대로 sanitize 후 전달이 필요한지 확정하고,
   필요한 경우 기존 위험 집계/STRICT 계약을 보존하는 Core 변경과 테스트를 작성해야 한다.
4. 임계값을 높이거나 실제 Guard를 mock으로 대체해서 통과시키지 않았다.
5. 재현: `uv run --group demo pytest -q -s tests/integration/test_mcp_sprint1_cross_boundary.py`
   C 케이스에서 expected ALLOW / actual BLOCK. 의도적으로 xfail 처리하지 않았다.

## 수정 파일과 후속 게이트

- src/runtime/mcp/executor.py, host_adapter.py: import 정렬만.
- tests/integration/test_mcp_enforcement.py: import 정렬/동등한 async context 병합.
- tests/integration/test_mcp_sprint1_cross_boundary.py: 실제 MCP 8개 후보 × B/C, Evidence 교차 검증.
- 본 문서: 검토·실행 결과·담당자 인계 기록.

필수 실패 해결 후 동일 SHA로 전체 pytest/Ruff/실서버 테스트를 재실행하고,
각 PR head와 체크 상태 재조회 후 #37 → #38 → #36 dev 병합 여부를 판단한다.
원격 dev 최종 재검증이 통과해야 G1 완료다. 현재 PR merge SHA는 모두 해당 없음.

Sprint 2: 실제 LLM의 다단계 Tool 선택, metadata/resource 신뢰 경계 검사,
fixture/demo 서버·인자 매핑, Error/Timeout/Fallback, server 측 호출 관측 sidecar,
평가 결과 Dashboard 연동, 정량 ASR/TSR/FPR 및 후속 Adaptive D.

## 교수님 미팅용 설명

“MCP SDK 기반 실제 Demo Server와 Runtime을 연결해 정상 파일 읽기와 이메일 시뮬레이션을
확인했습니다. 비인가 서버·정책 누락·경로 우회·외부 도메인은 서버 전송 전에 차단됩니다.
기존 세 PR의 전체 테스트는 통과했지만, 추가한 실서버 교차 검사에서 출력 마스킹 대신
출력 차단이 발생하는 계약 차이를 발견해 dev 병합을 보류했습니다. 담당자와 이를 해결하고
최종 dev 회귀를 마친 뒤 Sprint 1 통합 완료로 판정할 예정입니다.”

통합 완료, 실모델 공격 방어율 입증, 범용 MCP Host 지원, 실제 이메일 발송,
Adaptive D 완료라고 발표하면 안 된다.
