# 10/29 발표 실행 가이드

## 환경과 실행

프로젝트 루트(`pyproject.toml`, `uv.lock`, `demo/`가 있는 디렉터리)에서 실행한다.
이 PC의 저장소는 중첩되어 있으므로 바깥쪽 `main` 또는 `feat/platform-demo` 저장소와 혼동하지 않는다.

```powershell
cd C:\Users\jso25\OneDrive\Desktop\ai-agent-security-middleware\ai-agent-security-middleware\ai-agent-security-middleware-sprint2-demo
git branch --show-current
uv sync --frozen
uv run pytest -q
uv run ruff check .
uv sync --frozen --group demo
uv run --group demo streamlit run demo/dashboard.py
```

`demo`는 별도 dependency group이다. 일반 `uv sync --frozen`만 실행하면 Streamlit이 설치되지 않거나 제거될 수 있으므로 시연은 반드시 `--group demo`로 실행한다. CLI는 `uv run python demo/cli.py`로 계속 사용할 수 있다.

## 클릭 순서와 확인 항목

1. `Live Security Trace` → `🟢 정상 요청 실행`: Final Decision ALLOW, Tool 호출 1회, 출력 허용, 실제 문서 출력 확인.
2. 같은 화면에서 Evidence Event Count와 run_id / trace_id 일치 메시지를 확인한다.
3. `🔴 실행 전 공격 실행`: BLOCK, Tool 호출 0회, 출력 차단을 확인한다.
4. `🟠 실행 후 출력 차단 실행`: Tool 호출 1회와 실행 상태를 먼저 보여주고 출력 전달 차단을 확인한다. 실행과 출력 전달은 별도 통제임을 설명한다.
5. INPUT → CONTEXT → TOOL → OUTPUT 순서로 Guard 이름, 판정, 위험 점수, latency를 확인한다. Guard 판정과 최종 정책 판정은 다를 수 있다.
6. 아래 `Evidence 타임라인`에서 이벤트 순서와 단계를 확인한다. `DB에서 조회한 Evidence JSON`과 Runtime 반환값은 기본 접힘이며 질문이 있을 때 펼친다.
7. Sidebar의 `실행 선택`으로 이전 run을 조회한다. 새 버튼 실행 후에는 새 run이 자동 선택된다.
8. `A/B/C Evaluation` 탭에서 Baseline 0.80 → Mechanism Demonstration 순서로 표·PNG·표본 수·생성 시각을 설명한다.

실행 결과, execution state / executed, output allowed, policy reason / version, cumulative risk, run_id / trace_id, Evidence Timeline / Raw JSON은 기존과 같이 조회할 수 있다. 합성 API_KEY 출력은 개발자 상세에 보존되지만 차단된 출력은 전달 영역에 표시하지 않는다.

## Evaluation report 배치

기본 탐색 위치는 프로젝트 `reports/` 하위의 `summary.json`이다. 별도 위치라면 탭의 `Report directory`에 지정한다. 검증된 report 폴더를 그대로 배치하고 생성 시각·source commit·repeats·total trials를 확인한다. 이번 QA의 임시 smoke 결과를 발표용 360-trial 결과로 대체하지 않는다.

동일 폴더의 `summary.csv`, `rates.png`, `latency.png`를 재사용한다. PNG가 없어도 summary 표는 표시된다. Report가 없거나 잘못된 JSON이면 안내를 표시하며 Live 탭은 계속 사용할 수 있다. 수치는 summary에서 읽으며 UI가 재계산하지 않는다. 비율은 0–1, latency는 ms이다.

재생성이 필요할 때만 다음 명령을 사용한다. 출력 디렉터리는 존재하지 않아야 한다. 기존 검증 결과가 있으면 다른 새 경로를 사용한다.

```powershell
uv run python -m scripts.run_runtime_evaluation --output-dir reports/runtime_080 --repeats 30 --seed 42 --block-threshold 0.80
uv run python -m scripts.run_runtime_evaluation --output-dir reports/runtime_092 --repeats 30 --seed 42 --block-threshold 0.92
```

각 threshold는 180 trial, 두 report 합계는 360 trial이다. 작은 QA는 `--repeats 2`로 별도 임시 경로에만 실행한다.

## 설명 범위와 Known Issues

- A = No Guard, B = Independent Guards, C = Linked / Cross-layer Guards.
- 0.80은 baseline이다. 0.92는 Cross-layer 위험 누적 동작 차이를 확인하기 위한 시연용 설정이며, 일반적인 성능 우위를 증명하는 threshold가 아니다.
- 실제 Middleware Runtime / Security Core / Enforcement / SQLite Evidence와 Mock Tool을 사용한다. BENIGN-001 1종, ATTACK-001 1종을 조건별 반복한 초기 Evaluation Pipeline 검증 결과이며 전체 공격 환경에 대한 최종 보안 성능을 의미하지 않는다.
- ASR은 금지 send_email Tool 실행 기준이다. LLM 의미 품질이나 출력 유출 ASR을 평가한 결과가 아니다. 반복 seed는 현재 고정 fixture를 무작위 공격 표본으로 바꾸지 않는다.
- inspection mode / STRICT 전환은 현재 Evidence에 저장되지 않는다. UI는 이를 추론하지 않는다. 최종 누적 위험과 정책 버전만 기록된 값으로 설명한다.
- report 파일은 Git에 포함하지 않았다. 검증된 발표용 report의 별도 배치와 리허설이 필요하다.
- PR #14는 미통합이다. [감사 기록](PLATFORM_API_AUDIT.md)을 참고한다. 발표에 API 서버는 필요하지 않다.
- Windows sandbox에서 uv cache / pytest 임시 디렉터리 접근이 실패할 수 있다. 이번 baseline은 정상 권한에서 재실행해 확인했다. 권한 오류를 제품 실패나 성공으로 해석하지 않는다.
- 10/28에는 신규 개발 없이 이 순서로 리허설한다. 발표 전 두 탭, 세 버튼, report 경로와 생성 시각을 확인한다.

## 2026-10-27 QA 기록

기준 branch: `feat/presentation-dashboard`, base: `14c9ffec18dc4d9573354ebd11c47c944fb4ebdc` (PR #19 merge). 변경은 아직 commit / push / merge하지 않았다.

| 검사 | 결과 |
|---|---|
| 수정 전 `uv sync --frozen` | 정상 권한 재실행 성공; 최초 sandbox cache / network 오류는 환경 문제로 분리 |
| 수정 전 pytest / Ruff | 251 passed / All checks passed |
| 수정 후 `uv sync --frozen` | 성공 |
| 수정 후 pytest / Ruff | 254 passed / All checks passed |
| `git diff --check` | 통과 |
| Scenario 1 | ALLOW, Tool 1회, output allowed, Evidence 12건 |
| Scenario 2 | BLOCK, Tool 0회, output 차단, Evidence 9건 |
| Scenario 3 | BLOCK, Tool 1회, output 차단, Evidence 12건 |
| Evidence identity | 세 시나리오 모두 저장 run_id / trace_id 일치, Runtime errors 없음 |
| Evaluation smoke | repeats=2, threshold 0.80 / 0.92 각각 12 trial completed, 합계 24; 기존 report 덮어쓰기 없음 |
| Streamlit AppTest | 두 탭, 빈 실행 기록, report 없음, 세 실행 버튼, 새 run 자동 선택, 과거 run 선택, 실제 smoke report 두 표 표시 통과 |
| Report helper | 없는 경로, 실패 / malformed JSON, PNG 없는 summary 표와 원본 값 보존 검증 |

Evaluation smoke 산출물은 이 PC 임시 경로 `C:\Users\jso25\AppData\Local\Temp\presentation-qa-bt085q2m`에 있다. 기본 `reports/` 탐색 밖이며 공식 발표 결과가 아니다. 최종 UI smoke 데이터는 `C:\Users\jso25\AppData\Local\Temp\dashboard-final-rhge5cz4`에 있다. 임시 검증 스크립트는 제거했다.

최종 변경 파일은 `demo/dashboard.py`, `demo/reports.py`, `tests/unit/test_demo_reports.py`, 이 문서와 `docs/PLATFORM_API_AUDIT.md`다. generated Evidence / SQLite / report를 변경 파일에 포함하지 않았다. Security / Runtime / Enforcement / Evaluation metric / schema / threshold / pyproject / lock은 변경하지 않았다.

판단: 테스트 기준으로 dev 반영 후보로 적합하다. 실제 브라우저 화면의 시각 검수와 검증된 360-trial 발표 report 배치·리허설은 완료로 간주하지 않는다. 이 확인 후 freeze 여부를 결정한다.
