# GuardOn Sprint 1 통합 QA — 2026-11-19 (KST)

> 현재 판정은 하단의 **2026-11-20 정책 합의 및 통합 재개**와 최종 결과를 따른다.
> 아래 11/19 BLOCKED/수정 요청은 이력 보존이며 현재 정책 결함 판정이 아니다.

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

---

## 2026-11-20 정책 합의 및 통합 재개 (KST)

위 11/19 실패 기록은 당시 sanitize→ALLOW 기대값에 따른 역사적 결과다.
사용자가 전달한 Fatin/지원 검토 결론에 따라 B/C 모두 secret 출력 BLOCK이 의도된
정책임을 확정했다. 0.95 >= 0.80에서 Tool 실행 후 출력만 차단하며,
Security Core, Orchestrator, Threshold, Policy Version은 변경하지 않는다.

### 새 통합 기준과 변경

- 기존 11/19 worktree 및 원본 checkout의 미추적 파일을 보존했다.
- 새 worktree `.worktrees/mcp-sprint1-20261120`, 브랜치 `qa/mcp-sprint1-20261120`.
- dev `65052a4767219352a6e27e3e3d6dee7516f8cac5`에서 #37 → 최신 #38 → #36 순서로 통합.
- #37 head `c40cb67051a012f487e947f9c4a75c52dde254ba`.
- #38 최신 head `841acc54c8f68798ac5a554837b155129fbe6677`.
  기존 head 대비 import 정렬/async context 병합의 Ruff 수정임을 확인했다.
- #36 head `956d8c9c0dc36fd983814b24b8d459208c6b64fe`.
- 임시 통합 SHA `77231aab716c776b365f75fe039fa8cb6b545cb2`, 충돌 없음.
- #39를 병합하거나 이전 스타일 수정 커밋을 cherry-pick하지 않았다.
  신규 교차 테스트와 본 문서 두 파일만 복사했다.
- 교차 테스트의 secret 기대값을 B/C 공통 BLOCK으로 수정했다.
  호출 1회, executed=true, output_allowed=false, forward_output=None,
  sanitized_output=None, secret 미전달, OutputGuard 규칙/위험 0.95를 검증한다.
  기존 ALLOW/사전 차단 검증을 유지했고 skip/xfail은 추가하지 않았다.
- 두 조건의 모든 후보에서 SQLite decision/executed/execution_state/tool_call_id,
  run_id/trace_id 및 policy_version 정합성 검증이 끝까지 실행된다.

### 재실행 명령과 초기 결과

Windows PowerShell, CPython 3.12.13, frozen lock의 mcp/mcp-types 2.3.0.

```powershell
uv sync --frozen --group dev --group demo
.venv\Scripts\python.exe -m pytest -q -s tests/integration/test_mcp_sprint1_cross_boundary.py
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\ruff.exe check .
git diff --check
```

실서버 교차 테스트: **2 passed, 0 failed, 0 skipped**, 7.56초.
Ruff: All checks passed. diff check 통과.

### Known Limitations: 전달 차단과 저장 데이터 보호

B/C secret 후보 모두 실제 응답과 원시 ExecutionResult.output.content에
`API_KEY=sk-fake-sprint1`이 남는다. SQLite EXECUTION_RESULT payload.output.content에도
동일한 가짜 secret이 저장된다. 테스트가 DB에서 다시 읽어 이를 확인한다.
SECURITY_DECISION은 BLOCK, SECURITY_RESULT는 output_guard.secret_leakage / risk 0.95를
기록한다. output_allowed/forward_output은 Runtime 결과이며 별도 DB 필드가 아니다.

따라서 모델/사용자 전달 경계의 출력 보류는 검증했지만 원시 Evidence의
자동 redaction, 암호화, 접근권한/보존기간 관리는 이번 구현으로 보장하지 않는다.
실제 비밀정보를 넣지 않은 통제된 PoC이며 저장 데이터 보호는 Sprint 2 인계 항목이다.

### 2026-11-20 병합 전 전체 QA 및 원본 PR 병합

최신 #38을 반영한 임시 통합 + 수정 QA 테스트 전체 실행:
**725 passed, 0 failed, 0 skipped**, 73.13초. Ruff/diff check 통과.

각 병합 직전 Open/dev 대상, 아래 expected head, MERGEABLE/CLEAN,
statusCheckRollup 비어 있음을 재확인했다. expected_head_sha를 지정한 merge 방식으로
병합했고, 다음 PR 병합 전에 fetch 및 검증 트리와의 diff 일치를 확인했다.
dev 변경 직후 UNKNOWN 상태는 MERGEABLE/CLEAN 재조회 후 진행했다.

| 순서 | PR | 검증한 Head SHA | GitHub Merge SHA |
| --- | --- | --- | --- |
| 1 | #37 Security | c40cb67051a012f487e947f9c4a75c52dde254ba | 8c4bacaa4702e0b8c3d295828d15bda4a4649802 |
| 2 | #38 Runtime | 841acc54c8f68798ac5a554837b155129fbe6677 | a63b1148293ae4796cc1d7c98cf7e8c4f8063bb8 |
| 3 | #36 Evaluation | 956d8c9c0dc36fd983814b24b8d459208c6b64fe | 39637f2adafbb9a59fb8d2f7c9c38d328442e3d8 |

원본 세 PR 병합 후 dev HEAD는 `39637f2adafbb9a59fb8d2f7c9c38d328442e3d8`.
이 dev 전체 트리와 사전 검증 통합 커밋 `77231aa`의 git diff는 없다.
새 worktree `.worktrees/mcp-sprint1-dev-final-20261120`에서 origin/dev를 기준으로
최종 QA를 실행한다. 추가 QA PR은 이 dev에서 테스트/문서 두 파일만 추가한다.
#39는 병합하지 않았으며 그 원본 스냅샷은 보존했다.

### 2026-11-20 최종 dev 전체 회귀

최신 origin/dev `39637f2adafbb9a59fb8d2f7c9c38d328442e3d8`에서 추가 QA 파일을
넣기 전에 frozen sync 및 전체 pytest/Ruff/diff check를 재실행했다.

- 전체 pytest: **723 passed, 0 failed, 0 skipped**, 67.64초.
- Ruff: **All checks passed**.
- git diff --check: 통과.
- 기존 Runtime, A/B/C, Mock, Dashboard, Evaluation 회귀 포함.

이후 같은 dev에 QA 테스트/문서 두 파일만 추가하고 MCP enforcement/name-policy/
scenario 및 신규 cross-boundary 네 파일을 대상으로 실제 MCP 집중 검증을 재실행한다.
723과 신규 테스트 수를 합산하여 dev 전체 테스트 결과로 표시하지 않는다.

### 2026-11-20 최종 집중 QA 및 완료 판정: PASS

위 네 파일 집중 QA: **69 passed, 0 failed, 0 skipped**, 15.35초.
추가 파일을 포함한 Ruff/diff check도 통과했다. xfail/skip으로 실패를 숨기지 않았다.
dev 기반 QA 브랜치 `qa/mcp-sprint1-postmerge-20261120`는 본 문서와
test_mcp_sprint1_cross_boundary.py 두 파일만 추가한다. Core/설정/lock/원본 테스트 수정 없음.

B/C 각각 정상 read_file 1회 및 send_email 시뮬레이션 1회 ALLOW/전달,
evil/read_file·정책 누락·범위 밖 경로·traversal·비허용 도메인은 각각 호출 0회,
executed=false/BLOCK/미전달이었다. secret read_file은 각각 호출 1회,
executed=true/BLOCK/output_allowed=false/forward_output=None이다.
이는 명시적인 OutputGuard 탐지 후 출력 차단이며 실행 전 방어 성공으로 집계하지 않는다.
두 조건의 8개 후보 모두 SQLite 정합성 assertion을 통과했다.

따라서 **현행 보안 정책을 보존한 Sprint 1 통제된 MCP SDK 보안 연동 PoC의
원본 dev 통합 및 최종 회귀 검증 완료**로 판정한다.
별도 QA PR의 테스트/문서는 제출 산출물이며 이 문서 작성 시점 dev에는 추가하지 않았다.
기존 #39는 미병합 Draft로 보존하며 통째로 병합하지 않는다.

### 11/20 17:00 교수님 미팅에서 설명할 범위

“Security Core, 실제 MCP Runtime, 평가 명세의 원본 PR 세 개를 dev에 통합했습니다.
최종 dev 전체 테스트 723개와 추가 교차 테스트를 포함한 집중 검사 69개가 통과했습니다.
정상 파일 읽기와 이메일 시뮬레이션은 실제 MCP 호출로 확인했고, 비인가 서버·정책 누락·
경로 우회·외부 도메인은 호출 전에 차단합니다. 비밀정보가 든 파일은 읽기가 실행된 뒤
출력 전달을 차단하는 현행 B/C 정책을 확인했습니다. SQLite 기록도 실행·판정과 일치합니다.
실제 LLM 다단계 공격 평가와 저장 Evidence의 민감정보 보호는 후속 단계입니다.”

보장하지 않는 범위: 자동 마스킹 후 ALLOW, 원시 Evidence 비밀정보 제거/암호화,
실모델 ASR/TSR/FPR 입증, 범용 Host 지원, 실제 이메일 발송, MCP 오류/timeout 전용 E2E,
Adaptive D. 기존 11/19 ‘마스킹 수정 필수’ 요청은 정책 합의로 해소되었고 Core 수정 불필요다.

재현(Git Bash, 최종 QA worktree에서):

```bash
cd ~/OneDrive/Desktop/ai-agent-security-middleware/.worktrees/mcp-sprint1-dev-final-20261120
env -u VIRTUAL_ENV uv run --frozen --group demo pytest -q -s tests/integration/test_mcp_sprint1_cross_boundary.py
```
