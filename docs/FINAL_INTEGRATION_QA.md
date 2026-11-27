# 최종 통합 QA / Freeze

기준일: 2026-11-27 Asia/Seoul. 최종 코드 참조는 `guardon-freeze-20261127` tag이다. **코드 통합 완료와 새로운 실모델 실행/육안 화면 검사 완료는 구분한다.**

## 통합 순서와 보호 범위

원격 dev `d07d7c615b38b36a69a2307e8be26526e27432bb`에서 독립 worktree/branch `integration/final-20261127`를 만들었다. 기존 dev 작업 폴더, 다른 worktree/로컬 변경을 삭제하거나 덮어쓰지 않았다.

1. #45 Runtime → dev merge `18ee09314f4ede98f9e52df03807df057fbaee58`.
2. #46 Evaluation → dev merge `f50cf33cda48e3bd1d9b675bf1f9be231e811614`. Runtime 관련 7개 파일은 #45와 동일했고 재계산 후 55개 추가 파일이 남았다. 실제 평가 Backend·산출물 누락 없이 통합했다. 생성 SVG 5개의 줄 끝 공백을 전용 worktree에서 제거해 원래 PR에 fast-forward 추가했다(`3731de5717eb09c511558f984340a96329d6384a`). `git diff --ignore-space-at-eol --exit-code`로 비의미 변경임을 확인했다.
3. #47 확장 규칙은 Runtime/Evaluation을 결합한 상태에서 검증 후 dev merge `e26ca351ee227c1d439d3cef63ac6d21d3ba7f1e`. 기본 OFF, 기존 A/B/C 의미와 ToolPolicy/임계값/공통 DTO 유지.
4. Dashboard/Replay/공개 Runtime 인계 importer/시연 launcher/최종 문서를 별도 통합 PR로 반영한다.

#39와 #14는 이번 작업에 병합하지 않는다. #41은 발표 자료 작업으로 별도 유지한다.

## 실제 수행 결과

| 검사 시점 | pytest | Ruff | diff |
|---|---|---|---|
| #45 통합 | 1,218 passed / 2 skipped (280.29s) | PASS | PASS |
| #46 통합 | 1,325 passed / 2 skipped (237.25s) | PASS | SVG 공백 정리 후 PASS |
| #47 + 최종 Dashboard (`72add62956b6f74b33d38c9972b9ddc109123f5d`) | 1,349 passed / 2 skipped (227.51s) | PASS | PASS |

위 통합 커밋 전체 재실행 통과 후 #47을 병합했다. 마지막 dev merge SHA에서도 같은 전체 gate를 다시 실행하고 아래 SHA별 로그 및 Freeze tag로 확정한다. Git Bash에서 공개 결과 테스트 8개 통과, PowerShell 시연 스크립트 구문 검사 오류 0건을 확인했다.

새 Dashboard 첫 전체 실행에서는 테스트가 Streamlit 이미지 요소를 `imgs`로 잘못 조회해 실패했다. `image` 요소를 조회하도록 테스트 API 사용을 수정했으며 그래프 5개라는 검증 기준은 유지했다. 수정 후 해당 Dashboard 테스트는 통과했다. 기존 실패를 skip하거나 기존 보안 기대값을 완화하지 않았다.

기존 2개 skip은 `tests/integration/test_mcp_comparison_evidence.py:24`의 로컬 MCP comparison Evidence 부재다. 이번에 추가한 skip이 아니다. 실제 SDK 호출은 `test_mcp_server_call_count.py`, `test_mcp_transport_failures.py`, `test_agent_mcp_sdk_observation.py` 등의 실행 검증과 별도로 확인한다.

## 최종 SHA에서 재실행

```powershell
uv sync --locked --group dev --group demo
uv run python scripts/run_final_qa.py
git rev-parse HEAD
git rev-parse guardon-freeze-20261127
```

전체 pytest/Ruff/diff/commit diff를 실행하고 **실행한 HEAD SHA**와 exit code, 원본 로그를 `.cache/final-qa/<SHA>/result.json` 및 같은 폴더의 `pytest.txt`, `ruff.txt`, `diff.txt`, `commit_diff.txt`에 기록한다. 생성 로그는 Git에서 제외하며, 최종 응답에 기재한 dev SHA와 일치하는 결과만 최종 gate로 사용한다. 과거 팀원의 테스트 수를 합산하지 않는다.

## Dashboard와 데이터 QA

- 공개 48 Trial / 52 Candidate의 sample-condition 행렬, Trial/Candidate/Guard join, Evidence validated 수, status 집계 및 지표 분자/분모·rate를 교차 검사한다. 불일치하면 UI를 중단한다.
- 잘못된 run_id, 중복 Trial, 실행된 후보의 가짜 pre-block, 잘못된 rate를 주입해 거부함을 검사한다.
- AppTest에서 5개 분석 화면, 그래프 5종, 동일 표본 비교, Candidate 2단계 이동과 Runtime 호출 금지, 원본 파일 hash 불변을 검사한다.
- 실제 Streamlit 서버를 127.0.0.1:8501에서 기동했고 `/_stcore/health`는 `ok`였다.
- Runtime ZIP의 Agent 요약 29건을 공개 필드 allowlist로 가져온다. 원본 ZIP 및 항목별 hash를 보존하고 raw response/output/arguments 제거를 오류 주입 테스트로 검증한다. 별도 고정 후보 검증 16건은 외부 Benchmark나 Agent 실험 수에 합산하지 않는다.
- Desktop `1123_졸프` 폴더에서 Runtime, Dashboard, Adaptive D 및 External MCP 재현 ZIP을 확인했다. Dashboard ZIP의 내용은 SVG 공백을 제외하면 #46 자료와 동일했다. 비공개 원본 재집계 스크립트의 전체 실행은 하지 않았다.

## 미완료 검증 / Freeze의 한계

1. **새 실모델 E2E 미실행**: localhost:11434 연결 불가, LLM 환경변수 미설정, Ollama 실행 파일 미발견. 저장된 실제 Agent 기록 Replay를 검증했으며 신규 Qwen3:8b 성공으로 보고하지 않는다. 실모델 실행은 `FINAL_DEMO_GUIDE.md`의 명령을 사용한다.
2. **브라우저 육안 QA / MP4 미수행**: 연결된 in-app browser 목록이 비어 있었다. AppTest와 서버 smoke는 수행했으나 실제 viewport에서 잘림·색·가독성 검사를 완료했다고 주장하지 않는다. 자동 녹화 MP4도 없다.
3. **비공개 Evidence 원본 재감사 미수행**: 공유 JSON의 식별자·집계 일관성 검사와 원본 SQLite payload 재검증은 다르다. 공식 ASR/TSR/FPR은 N/A를 유지한다.

이 한계는 코드 변경으로 우회하지 않는다. 최종 tag는 검증된 통합 코드 참조이며 위 미수행 검증까지 모두 완료되었다는 선언이 아니다.
