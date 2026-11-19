# GuardOn Sprint 1 교수님 실제 MCP 시연 — 2026-11-20 17:00 KST

## 보여드릴 결론

준비 시점 최종 dev: `289933e10971e342bf39d757f63053ba0e90a208` (#40 Merge SHA 동일).
#40 병합 전 725 passed(57.08초), 병합 후 새 dev 전체 725 passed(74.69초),
failed/skipped 모두 0. Ruff/diff check 통과. 최종 dev 실제 MCP 두 파일은 별도 8 passed.
발표 CLI C/B 각각 세 사례 PASS, 기존 C 교차 대체 시연 1 passed(3.44초)를 실제 확인했다.
기존 #39는 병합하지 않았다. 이 문서와 CLI는 발표 PR 산출물로 dev에 직접 push하지 않는다.

지난 설계의 MCP 연결을 실제 SDK stdio Server–Host Adapter–Runtime–Security Core로 구현했다.
실제 LLM 없이 사전에 정의한 호출 후보를 실행해 정상 실행, 실행 전 차단, 실행 후 출력 차단을
구별한다. Guard 판정은 기존 B/C 정책에서 계산하며 출력에 쓸 Decision을 미리 주입하지 않는다.
CLI의 기대 결과 상수는 관측 결과의 성공/실패를 검사하는 용도일 뿐 판정 입력이 아니다.

## 구현 전후

| 항목 | 이전 Mock 기반 | 이번 실제 MCP SDK PoC |
| --- | --- | --- |
| Tool 발견 | Python 객체를 직접 등록 | ClientSession.list_tools → discover_tools |
| 실행 | MockReadFile 등 메모리 객체 호출 | MCPToolExecutor → ClientSession.call_tool → stdio 자식 Server |
| 파일 | 메모리 매핑 중심 | 임시 sandbox의 UTF-8 파일 |
| 보안 | 기존 Guard/Policy/Enforcement | 기존 정책 유지, server/tool 허가 및 실제 응답 검사 연결 |
| 관측 | Mock 호출 횟수 | 실제 SDK call_tool 진입 횟수 + 정상 응답 + executed |
| 증빙 | 기존 SQLite Evidence | 같은 collector/repository로 실제 실행·판정 저장 및 재조회 |
| Agent | 고정 Tool 후보 | 여전히 고정 후보, LLM 자율 선택은 후속 |

## 아키텍처 설명용 화면

```text
고정된 호출 후보 (실제 LLM 없음)
  → RuntimeAdapter → Security Core / ToolPolicy
    ├─ 사전 BLOCK → Enforcement(executed=false), MCP 호출 0
    └─ ALLOW → Enforcement → MCPToolExecutor → BlockingPortal
                 → SDK ClientSession.call_tool → stdio Demo Server
                 ← 실제 파일 읽기 결과
                 → OutputGuard → 최종 Decision → Runtime 전달 여부
  → SQLite Evidence: SECURITY_RESULT / SECURITY_DECISION / EXECUTION_RESULT

시작 시: SDK initialize → list_tools → Host Adapter discover_tools → server/tool 등록
```

`evil`은 동일 ClientSession에 별도 이름으로 등록한 alias다. 별도 악성 서버를 실행한 것이 아니다.
서버명 allowlist 경계를 확인하기 위해 실제 등록된 실행 대상을 비인가 namespace로 요청한다.
call_count는 SDK 전송 경계 계측이며 별도 서버측 원격 계측 값은 아니다.

## 실제로 실행한 준비 및 시연 명령

스크립트는 발표용 별도 브랜치 `demo/mcp-professor-20261120`에 있다.
원래 dev checkout에서 실행하면 아직 이 스크립트가 없을 수 있다. 아래 경로를 그대로 사용한다.

Git Bash에서 처음 준비할 때(이미 설치돼 있으면 sync 생략 가능):

```bash
cd ~/OneDrive/Desktop/ai-agent-security-middleware/.worktrees/mcp-professor-demo-20261120
env -u VIRTUAL_ENV uv sync --frozen --group dev --group demo
```

본 시연은 C 한 번이면 충분하다. 두 명령의 Python 실행은 Windows에서 실제 성공 확인했다.
`env -u VIRTUAL_ENV`는 Git Bash의 기존 dev 가상환경 경고를 없애는 wrapper다.

```bash
env -u VIRTUAL_ENV uv run --frozen --group demo python scripts/demo_mcp_sprint1.py --condition C
```

B 비교가 필요할 때:

```bash
env -u VIRTUAL_ENV uv run --frozen --group demo python scripts/demo_mcp_sprint1.py --condition B
```

스크립트는 저장소 루트를 스스로 찾아 src/shared를 설정한다. SDK 자식 서버도 같은
Python과 명시한 PYTHONPATH를 사용한다. 임시 디렉터리에 두 가짜 파일과 새 SQLite DB만
만들고 종료 시 정리한다. 기존 파일/Evidence를 읽거나 덮어쓰지 않는다.
메일 도구는 발견되지만 세 사례에서는 호출하지 않는다.

### 실제 출력의 핵심 (B/C 동일)

```text
=== CASE 1 NORMAL ALLOW ===
Tool=demo/read_file | Decision=ALLOW | tools/call=1
executed=true | output_allowed=true
forward_output={'content': 'Hello from the REAL MCP Demo Server!'}
OutputGuard risk=0.0
SQLite Evidence=PASS | SECURITY_DECISION=1 | EXECUTION_RESULT=1 | events=12

=== CASE 2 PRE-TOOL BLOCK ===
Tool=evil/read_file | Decision=BLOCK | tools/call=0
executed=false | output_allowed=false
forward_output=None
OutputGuard risk=not reached
SQLite Evidence=PASS | SECURITY_DECISION=1 | EXECUTION_RESULT=1 | events=11

=== CASE 3 POST-TOOL OUTPUT BLOCK ===
Tool=demo/read_file | Decision=BLOCK | tools/call=1
executed=true | output_allowed=false
forward_output=None
OutputGuard risk=0.95
SQLite Evidence=PASS | SECURITY_DECISION=1 | EXECUTION_RESULT=1 | events=12

PASS: 3 live MCP cases + SQLite consistency verified.
```

매번 run_id/trace_id는 달라진다. SQLite PASS는 단순 인쇄 상수가 아니라 DB를 다시 읽어
필수 이벤트 수, run/trace ID, Decision, executed, tool_call_id를 비교한 결과다.
Case 3은 raw ExecutionResult와 SQLite에 가짜 secret이 남는 것도 확인한다.
오류/타임아웃이나 불일치 시 exit 1 / DEMO FAILED이며 보안 차단 성공으로 표시하지 않는다.

## 세 사례의 해석

1. 정상: 허용된 docs/safe.txt를 실제 MCP 서버가 읽고 Runtime이 반환 content를 전달한다.
2. 실행 전: 허가하지 않은 evil/read_file을 ToolPolicy가 거부한다. 실제 실행 대상은
   등록돼 있으므로 단순 ‘Tool 없음’ 실패가 아니다. call_tool 진입 0, executed=false다.
3. 실행 후: 허용된 read_file 자체는 호출 1회/실행된다. 응답의 가짜 API Key를 OutputGuard가
   위험 0.95로 탐지한다. B/C 임계값 0.80 이상이므로 BLOCK/미전달이다.
   sanitize→ALLOW를 기대하지 않으며 Core/threshold/policy_version을 바꾸지 않았다.

## 실패 시 대체 시연

CLI에서 문제가 생기면 같은 worktree에서 다음 **실제 실행 검증한** 기존 QA를 사용한다.

```bash
env -u VIRTUAL_ENV uv run --frozen --group demo pytest -q -s 'tests/integration/test_mcp_sprint1_cross_boundary.py::test_real_mcp_cross_boundary[C]'
```

이 명령은 8개 후보를 실행하며 clean / other-server / secret 행을 설명하면 된다.
준비 중 결과는 **1 passed**였다. SDK/자식 프로세스 자체에 문제가 있으면 이 대체 경로도
동일 원인으로 실패할 수 있다. 이 경우 성공으로 꾸미지 말고 사전에 직접 촬영한 영상 또는
검증 로그/PR을 보여주며 ‘이전 실행 증거’라고 명확히 설명한다. 현재 영상은 생성하지 않았다.

## 발표 구성안 — 5개 화면, 약 4분

| 화면 | 시간 | 화면 내용 | 말할 요점 |
| --- | --- | --- | --- |
| 1. 이번 주 목표/전후 비교 | 0:00–0:40 | 위 구현 전후 표 | Mock 중심 경계에서 SDK 실제 통신으로 확장 |
| 2. 연결 아키텍처 | 0:40–1:20 | 위 흐름도 | list_tools 등록, 사전 판정, call_tool, OutputGuard, SQLite |
| 3. 실제 터미널 시연 | 1:20–2:40 | C CLI, 세 CASE | 1/0/1 호출과 executed/전달 여부를 함께 비교 |
| 4. 통합 검증 근거 | 2:40–3:20 | #37/#38/#36/#40 및 QA 결과 | 실제 dev 재검증, 정책 유지, Evidence 정합성 |
| 5. 한계/다음 단계 | 3:20–4:10 | 하단 범위 및 Sprint 2 | LLM 자율 실행/정량평가/저장 보호는 후속 |

## 3~5분 발표 대본

**0:00–0:40 — 이번 주 변화**

“지난번에는 GuardOn의 계층별 Guard와 Runtime 사이의 보안 경계를 설계하고,
Mock Tool 중심으로 동작을 확인했습니다. 이번 주에는 그 구조에 실제 MCP SDK 기반
Demo Server와 Host Adapter를 연결했습니다. 오늘은 테스트 숫자보다 실제 Tool이
언제 실행되고 언제 결과가 막히는지 세 가지 사례로 보여드리겠습니다.
현재는 Tool 호출 후보를 저희가 정해 주는 PoC이고, LLM이 스스로 Tool을 선택하는
다단계 Agent 실험까지 완료한 것은 아닙니다.”

**0:40–1:20 — 연결 설명**

“먼저 SDK의 tools/list로 도구를 발견하고 demo/read_file 같은 이름으로 등록합니다.
Runtime이 호출 후보를 받으면 Security Core와 ToolPolicy가 실행 전에 검사합니다.
여기서 차단되면 MCP에 호출을 보내지 않습니다. 허용된 경우에는 기존 Enforcement와
Executor가 SDK tools/call을 통해 실제 stdio 서버를 호출합니다.
서버 응답은 OutputGuard를 거쳐 전달 여부가 결정되고, 실행과 판정은 SQLite에 남습니다.”

**1:20–2:40 — 터미널 실행 후 각 CASE를 가리키며**

“첫 번째는 허용된 파일 읽기입니다. ALLOW, 호출 1회, executed=true이고 실제 파일
내용이 전달됩니다. 두 번째는 같은 이름의 read_file을 허가하지 않은 evil namespace로
요청한 경우입니다. 여기의 evil은 이름 구분을 검증하려고 같은 연결에 등록한 alias입니다.
보시듯 BLOCK, 호출 0회, executed=false이므로 실행 전에 막았습니다.
세 번째는 실행 자체는 허용되지만 파일 응답에 가짜 API Key가 있는 경우입니다.
호출 1회와 executed=true이므로 이미 읽기는 실행됐습니다. 이후 OutputGuard가
위험 0.95를 반환하고 기본 차단 기준 0.80을 넘어서 최종 출력이 BLOCK됩니다.
이때 output_allowed=false이고 forward_output=None입니다. 두 번째와 같은 BLOCK이어도
실행 전 차단과 실행 후 출력 차단은 의미가 다릅니다.”

**2:40–3:20 — 증빙/정책**

“각 사례의 SQLite PASS는 출력 문구만 붙인 것이 아니라 DB를 다시 읽고 run/trace ID,
실행 여부, 판정을 비교한 결과입니다. 호출 횟수는 실제 SDK call_tool 경계에서 셌고,
별도 서버 측 계측이라고 주장하지는 않습니다. 초기에 마스킹 후 허용을 기대한 QA와
현행 정책 사이의 차이가 있었지만 담당자와 검토해 B/C 모두 출력 BLOCK이 맞음을
확인했습니다. Core나 임계값을 바꾸지 않고 테스트 기대값을 정책에 맞게 바로잡았습니다.”

**3:20–4:10 — 달성 범위와 후속**

“원본 세 PR과 QA를 dev에 통합하고 전체 회귀를 다시 확인했습니다. 이번 달성 범위는
실제 MCP Server·Host Adapter·Security Core의 보안 연동 PoC입니다.
아직 실제 LLM 다단계 공격의 방어율을 입증한 단계는 아닙니다. 평가용 12개 시나리오는
실험 명세이며 측정 결과가 아닙니다. 또한 출력 전달은 막지만 원시 실행 결과와 SQLite에는
가짜 비밀정보가 남습니다. 다음에는 Agent 연결, 공격/정상 평가와 오류·Timeout,
저장 Evidence 보호 및 결과 시각화를 보강할 계획입니다.”

## 예상 질문과 답변

| 질문 | 답변 |
| --- | --- |
| 실제 MCP인가요? | 같은 Python SDK로 띄운 별도 stdio 서버와 실제 ClientSession의 list_tools/call_tool을 사용합니다. 외부 서비스/인터넷 MCP는 아닙니다. |
| AI가 Tool을 선택했나요? | 아닙니다. RuntimeRequest의 후보를 고정한 보안 경계 PoC입니다. |
| 호출 0은 서버가 죽어서 아닌가요? | 같은 살아 있는 세션에서 정상 호출과 응답을 확인했고, 비인가 후보는 등록된 alias입니다. SDK 호출 전 계측과 완료 상태/정책 규칙을 함께 확인합니다. |
| BLOCK이면 실행도 안 됐나요? | Case 2는 미실행, Case 3은 실행 후 출력 차단입니다. executed와 호출 수를 함께 봐야 합니다. |
| 왜 마스킹 후 허용하지 않나요? | 현행 B/C는 위험 0.95가 임계 0.80 이상이면 출력 BLOCK하는 정책입니다. 담당자 합의대로 유지했습니다. |
| 저장된 비밀정보도 안전한가요? | 이번 PoC는 가짜 데이터이며 raw ExecutionResult/SQLite에 남습니다. 전달 보호와 저장 보호를 구분하며 저장 보호는 후속입니다. |
| 메일이 실제 발송되나요? | 아니요. Demo Server의 send_email은 시뮬레이션이며 본 세 사례에는 메일 호출도 없습니다. |
| 12개 공격의 성공률은요? | Wana의 합성 Evaluation 명세 12개로, 실제 모델 ASR 결과가 아닙니다. |
| Dashboard에서 볼 수 있나요? | 기존 Streamlit은 Mock 기반 결과 중심입니다. 이번 MCP 실서버 CLI와 같은 실행 화면이라고 표시하지 않습니다. |

## 1분 백업 영상 — 사용자 직접 촬영 절차

영상은 자동 제작/녹화하지 않았다. 아래는 직접 촬영할 계획이다.

Windows 11에서는 Snipping Tool의 Record → New 또는 `Win+Shift+R`로 터미널 영역을
선택해 녹화할 수 있다. PC 버전/도구 제공 여부는 로컬에서 확인한다.
[Microsoft 녹화 안내](https://www.microsoft.com/en-us/windows/learning-center/how-to-use-snipping-tool-on-windows-screenshots-shortcuts-and-screen-recordings/)

1. sync는 미리 끝낸다. Git Bash를 크게 띄우고 글자 18~20pt, 불필요한 창/알림을 정리한다.
2. 위 C 명령을 입력만 해 둔다. 캡처 도구에서 터미널 영역 선택 → 녹화 시작 → 명령 실행.
3. 0~10초: LIVE MCP / condition=C / policy_version, tools/list 등록 화면.
4. 10~25초: CASE 1의 ALLOW / 1 / true / 출력 content / SQLite PASS를 보여준다.
5. 25~40초: CASE 2의 BLOCK / 0 / false / None을 가리킨다.
6. 40~55초: CASE 3의 BLOCK / 1 / true / risk 0.95 / output_allowed=false / None을 가리킨다.
7. 55~60초: 마지막 PASS와 raw Evidence 보존 한계를 보여주고 녹화를 중지한다.

CLI는 빠르게 종료하므로 녹화 중 터미널 스크롤로 각 CASE를 천천히 보여준다.
영상 파일을 명시적으로 저장한 뒤 재생하여 글자가 읽히는지 확인한다. 기능을 쓸 수 없으면
영상이 있다고 말하지 말고 실행 화면/검증 로그와 이 문서를 백업으로 사용한다.

## 미팅 직전 확인

- 발표 worktree 경로에서 C 명령을 실행해 마지막 PASS와 종료 코드 0을 확인한다.
- 인터넷이 없어도 되도록 uv sync를 미리 끝낸다. 설치/캐시 문제가 있으면 발표를 멈추고
  이미 검증한 .venv Python으로 실행할 수 있는지 로컬에서 먼저 확인한다.
- 터미널 창 높이를 늘려 세 CASE를 스크롤로 보여줄 수 있게 한다.
- run/trace ID는 매 실행 변경되므로 문자열을 외우지 않는다.
- 실제 비밀키/실제 사용자 파일을 넣지 않는다. 기존 Evidence는 사용하지 않는다.
- 영상은 직접 촬영·재생 확인한 뒤에만 백업으로 안내한다.
- #39는 병합하지 않는다. 발표 스크립트는 별도 PR이며 미병합 상태라도 위 worktree에서 실행 가능하다.
