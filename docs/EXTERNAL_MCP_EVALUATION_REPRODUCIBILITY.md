# 외부 MCP 벤치마크 평가 결과 재현 및 인계 가이드

## 1. 범위와 실행 기준

이 문서는 이미 저장된 실제 LLM-MCP 실험 결과의 오프라인 재집계 및 추가 분석 절차를 설명합니다. 새로운 LLM 추론이나 Runtime 실행은 필요하지 않습니다. 후속 보고서 정리 Commit은 실험 실행 Commit과 구분합니다.

- 실험 실행 Commit: `85bb698e8cf38e8dbbb0cfcdc2a189cf12954948`
- 실행 fingerprint: `a41337b74e0f3939cfda64c96947fafcfe7bbf9f7890c71b7a1dade60e1b40f0`
- 실행 설정: [experiment_configuration.json](../reports/external_mcp_actual/experiment_configuration.json)
- 환경 버전: [dependency_versions.json](../reports/external_mcp_actual/dependency_versions.json)
- 결과 요약: [EXTERNAL_MCP_EVALUATION_RESULTS.md](EXTERNAL_MCP_EVALUATION_RESULTS.md)

## 2. 공유 파일 구성

저장소에는 `docs/`의 결과 문서와 `reports/external_mcp_actual/`의 공유용 Dashboard, 실행 설정 및 환경 manifest를 포함합니다. 검증된 원본 분석 스크립트는 바이트 단위 무결성을 유지하기 위해 별도 재현 번들로 전달합니다.

- `GuardOn_Sprint3_Dashboard_Handoff.zip`: Dashboard 연동용 CSV/JSON, 지표 정의, README, PNG/SVG 그림.
- `guardon-submission-repro-20261127-095658.zip`: 위 Dashboard, 수집·분석·검증 스크립트, 실행 설정, QA 기록, README 및 SHA-256 manifest. 팀 제출 시 별도 첨부합니다.
- 재현 번들 SHA-256: `90e1f8f5038f6446b719aaa61dde4cd3489b4d2ad3350f767f32ac13423265dc`

원본 Benchmark 데이터, 실제 모델 응답, 로그, SQLite Evidence 및 비공개 원본 검증 파일은 공유 대상이 아닙니다. 결과 조회에는 비공개 입력이 필요하지 않지만 전체 재계산에는 해당 자료에 대한 적절한 접근 권한이 필요합니다.

## 3. 재현 환경

Windows, Python 3.12.13 및 실험 당시 Commit을 사용합니다. 별도의 재현용 설치 환경에서 저장소의 `uv.lock`을 기준으로 `uv sync --locked --group dev`를 실행합니다. 기존 실행 환경이나 작업 중인 브랜치를 변경하지 않습니다.

현재 도구는 아래 절대 경로와 원본 자료의 이름을 전제로 합니다. 임의 경로에서 즉시 재현되는 형태는 아닙니다.

```text
C:\Projects\ai-agent-security-middleware
C:\Projects\guardon-external-benchmarks
C:\Projects\guardon-evaluation-output
```

`guardon-evaluation-output`의 원본 실험 폴더, continuation 폴더, 최종 consolidated 보고서 폴더를 이름 및 내용 변경 없이 보존해야 합니다.

```text
sprint3-primary-pit01-on-t600-20261127-013842
sprint3-primary-pit01-on-t600-20261127-013842-continuation
sprint3-primary-pit01-on-t600-20261127-013842-consolidated-20261127-065839-549930
```

번들의 `scripts/`에 포함된 네 파일을 외부 evaluation-output 폴더에 배치합니다. 기존 파일이 있으면 덮어쓰기 전에 해시를 확인합니다. `guardon_continuation.py`는 고정된 감사 함수 의존성으로 사용합니다. 실행 모드(`--run`)는 호출하지 않습니다. 원본 Evidence의 ID·경로·해시를 임의로 수정하지 않습니다.

## 4. 오프라인 재현 명령 (PowerShell)

```powershell
$py = 'C:\Projects\ai-agent-security-middleware\.venv\Scripts\python.exe'
$root = 'C:\Projects\guardon-evaluation-output'

& $py -B "$root\guardon_collect_consolidated.py" --self-test
& $py -B "$root\guardon_supplemental_analysis.py" --self-test

& $py -B "$root\guardon_collect_consolidated.py" --graphs
& $py -B "$root\guardon_supplemental_analysis.py" --graphs
```

각 보고 실행은 새 출력 디렉터리를 생성합니다. 추가 분석기는 기본적으로 확정된 `065839-549930` consolidated 결과를 사용하며, 새 collector 실행 결과로 자동 변경하지 않습니다. `SNAPSHOT_COMPLETE.json` / `ANALYSIS_COMPLETE.json`이 있는 완료된 결과를 사용합니다. 재분석 결과를 새로운 실험 시도로 합산하지 않습니다.

새 추가 분석 디렉터리에 대해 독립 검증을 수행합니다.

```powershell
& $py -B "$root\guardon_validate_supplement.py" --report '<새 추가 분석 디렉터리의 전체 경로>'
```

검증 파일은 덮어쓰기를 방지하므로 이미 검증한 디렉터리에서는 다시 실행하지 않습니다. 상세 전제 조건은 번들의 `README.txt`를 참고합니다. 이 절차에 모델 프로세스, API Key, 실험 실행 CLI는 필요하지 않습니다.

## 5. 무결성 및 QA

번들의 `SHA256SUMS.json`은 내부 42개 파일에 대한 해시를 기록합니다. 전체 ZIP 해시와 내부 파일 해시를 검증하여 전송 중 변경 여부를 확인할 수 있습니다.

실험 Commit 기준 QA 결과는 pytest 1,307 passed / 3 skipped, Ruff 및 git diff check 통과입니다. 별도 보고 스크립트 자체 테스트 26개와 독립 검증도 통과했습니다. 실행 결과 및 상세 감사 내용은 번들의 `FINAL_QA.json`, `FINAL_QA.txt`, `verified_analysis_qa.json`에 있습니다. 후속 문서 Commit은 별도로 검토합니다.

## 6. Dashboard 적용 시 주의사항

`dashboard/summary.json` 및 `report_summary_ko.json`을 요약 출처로 사용합니다. 분자·분모·단위·분석 범위·제외 사유를 함께 표시합니다. null/N/A는 0%가 아닙니다. 완료 실험에 대한 주 분석과 Timeout/오류의 진단 범위를 분리하고, 기존 공식 ASR/TSR/FPR을 사후 관찰 지표로 덮어쓰지 않습니다.

실행 결과는 표본별 단일 반복의 기술통계입니다. 생성 응답의 의미 기반 판정 범위, 사용자 전달 및 모의 전송 감사의 한계는 결과 문서와 Dashboard README를 참고합니다.
