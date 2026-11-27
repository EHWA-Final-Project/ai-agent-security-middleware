# GuardOn 최종 시연

## 한 번에 실행: 저장된 실제 결과

저장소 루트의 PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/start_final_demo.ps1 -Mode Replay
```

브라우저: http://127.0.0.1:8501 . 이미 같은 포트를 사용하면 `-Port 8502`를 지정한다.

Git Bash:

```bash
uv sync --locked --group dev --group demo
uv run streamlit run demo/final_dashboard.py --server.address 127.0.0.1 --server.port 8501 --server.headless true --browser.gatherUsageStats false
```

## 6장면 화면 순서

1. **Overview**: 12표본, 48시도, 41완료/5Timeout/2오류, 아키텍처, 공식 지표 N/A를 설명한다. 저장된 실제 결과라는 배너를 보여준다.
2. **Actual Agent–MCP → Runtime 인계**: `abcd_multistep / C` 또는 D. 모델 턴 1·2의 read_file, SDK tools/list와 tools/call, 두 Candidate의 서버 진입, 후속 모델 전달과 최종 응답 관측을 설명한다. policy_version/PI-T01/초기 검사 모드를 함께 보여준다.
3. 같은 화면에서 `abc_normal_preblock / C / external-unauthorized-email-001`: Tool 미실행·SDK 호출 0을 확인한다. 이전 구현의 호출별 SDK 목록이 없는 경우 ‘기록 없음’을 0과 구분한다. 후보의 명시적 sdk_call_count와 server_call_counts를 사용한다.
4. `abc_postblock / C / external-output-block-001`: EXECUTED와 BLOCK, Tool 실행 1회, output_allowed/output_delivered=false를 확인한다. 원문은 화면에 표시하지 않는다. `d_boundary`의 PI-T01 ON/OFF 기록도 별도로 비교한다.
5. **A/B/C/D Comparison**: `bipia-table-pair-001:attack`. A의 후속 send_email 실행, B/D의 ToolPolicy 차단, C Timeout을 보여준다. **External Benchmark**에서 조건별 완료 수, 5종 그래프, 분자·분모·scope·제외 사유를 설명한다.
6. **Evidence / Replay**: Trial/Runtime Run/Trace/Candidate/Evidence ID를 확인하고 Candidate 순서를 이동한다. 사이드바 Workbench는 Fixture/Mock 자료임을 설명한다. Workbench의 합성 정상/실행 전/실행 후 시나리오 실행 뒤 로컬 SQLite Replay가 가능하다. 이 실행은 실제 LLM 실험과 별도다.

Runtime 인계 요약은 29 Agent 기록이며 별도 고정 후보 실제 MCP 검증 16건과 외부 Benchmark 48시도에 합산하지 않는다. SDK 호출은 서버 진입과 다르다. 출력의 모델 전달은 사용자 전달과 다르다.

## 실제 Qwen3:8b 실행

전제: 사용자가 관리하는 Ollama에 `qwen3:8b`가 설치·기동되어야 한다. 이번 통합 환경에서는 localhost:11434에 연결되지 않았으며 새 실모델 E2E 성공을 주장하지 않는다. Replay에는 모델 서버가 필요 없다.

```powershell
powershell -ExecutionPolicy Bypass -File scripts/start_final_demo.ps1 -Mode Live-Normal -Condition C
powershell -ExecutionPolicy Bypass -File scripts/start_final_demo.ps1 -Mode Live-PreBlock -Condition C
powershell -ExecutionPolicy Bypass -File scripts/start_final_demo.ps1 -Mode Live-Injection -Condition D
```

스크립트는 PI-T01 ON으로 실행하며 현재 확장 규칙은 기본 OFF다. 로그의 정확한 policy_version을 촬영한다. 출력은 `%LOCALAPPDATA%\GuardOn\demo\<새 GUID>`에 저장된다. 로그/SQLite 원본을 Git에 추가하지 않는다. 모델이 예상 Tool을 선택하지 않거나 Timeout이면 성공으로 설명하지 않는다.

Git Bash의 직접 실행 예:

```bash
export LLM_BASE_URL=http://127.0.0.1:11434/v1
export LLM_MODEL=qwen3:8b
export LLM_MAX_TOKENS=2048
export LLM_TIMEOUT_SEC=600
uv run python examples/run_agent_mcp_e2e.py --condition C --pit01 --scenario normal
```

`--output-dir` 없이 실행하면 임시 Evidence는 종료 후 삭제된다. 보존 시 저장소 외부의 새 경로를 지정한다. API 키가 필요한 서비스는 환경변수를 사용하며 키를 화면·명령 인자·공유 파일에 쓰지 않는다.

## 실제 SDK 경계 검증

```powershell
uv run pytest -q tests/integration/test_mcp_server_call_count.py tests/integration/test_mcp_tool_response_injection.py tests/integration/test_mcp_transport_failures.py tests/integration/test_agent_mcp_sdk_observation.py
```

위 검사는 실제 MCP stdio SDK를 포함하지만 LLM 선택은 Fixture/고정 후보를 사용할 수 있다. 실모델 실험과 구분한다.

## 녹화

자동 화면 녹화와 MP4는 이번 환경에서 생성하지 않았다. 사용자 PC의 Snipping Tool 화면 녹화 또는 화면 녹화 프로그램에서 실제 브라우저와 터미널을 선택해 위 6장면을 촬영한다. Replay 구간은 저장된 실제 결과 배너가 보이도록 녹화한다. 실모델 구간은 터미널의 model/policy/SDK/server/output 경계를 함께 보여준다. 최종 산출물은 MP4로 저장하고 재생해 텍스트·표·그래프가 읽히는지 확인한다.
