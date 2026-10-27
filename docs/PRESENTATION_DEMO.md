# 10/29 발표 실행 가이드

## 환경과 실행

프로젝트 루트(`pyproject.toml`, `uv.lock`, `demo/`가 있는 디렉터리)에서 실행한다.
이 PC의 저장소는 중첩되어 있으므로 바깥쪽 `main` 또는 `feat/platform-demo` 저장소와 혼동하지 않는다.

```powershell
cd C:\Users\jso25\OneDrive\Desktop\ai-agent-security-middleware\ai-agent-security-middleware\ai-agent-security-middleware-sprint2-demo
git branch --show-current
uv sync --frozen --group demo
uv run --group demo pytest -q
uv run --group demo ruff check .
uv run --group demo streamlit run demo/dashboard.py
```

`demo`는 별도 dependency group이다. 일반 `uv sync --frozen`만 실행하면 Streamlit이 설치되지 않거나 제거될 수 있으므로 시연은 반드시 `--group demo`로 실행한다. CLI는 `uv run python demo/cli.py`로 계속 사용할 수 있다.

Git Bash에서는 경로에 `/`를 사용한다. 바깥쪽 `feat/platform-demo` 저장소에 있다면 `cd ai-agent-security-middleware-sprint2-demo` 후 위 Streamlit 명령을 실행한다. 또는 다음 절대 경로를 사용한다.

```bash
cd /c/Users/jso25/OneDrive/Desktop/ai-agent-security-middleware/ai-agent-security-middleware/ai-agent-security-middleware-sprint2-demo
uv run --group demo streamlit run demo/dashboard.py
```

## 클릭 순서와 확인 항목

1. `Plugin Execution Trace`에서 상단의 다섯 단계 안내와 세 시나리오 카드를 보여준다. 카드의 예상 결과와 실행 후 실제 결과를 구분한다.
2. `정상 요청` 카드의 `실행`: 큰 요약 카드에서 ALLOW, Tool 실행됨, Output 전달, Evidence 저장 확인을 보여준다. 실제 문서 출력은 `실행 상세 · 정책 / 출력 / 식별자`에서 확인한다.
3. `▶ 흐름 재생`: 저장 이벤트를 자동 재생한다. `처음으로` → `⏭ 다음 단계`로 한 이벤트씩 진행할 수도 있다. `전체 결과`는 최종 화면으로 돌아간다.
4. `공격 시도 차단` 카드의 `실행`: BLOCK, Tool 미실행, 출력 차단을 확인한다. 새 run은 자동 선택되고 Replay도 해당 run 기준으로 초기화된다.
5. `실행 후 출력 차단` 카드의 `실행`: Tool 실행됨, 출력 차단을 확인한다. Replay의 Enforcement → OUTPUT Guard 순서는 저장 순서 그대로다.
6. 가로 파이프라인의 현재 단계와 실제 ALLOW / WARN / BLOCK을 설명한다. Plugin Manager는 별도 이벤트가 없는 구조 카드이며 재생 상태를 만들지 않는다. `Evidence · SQLite`에서 저장 count와 조회 상태를 확인한다. `⑤ 저장된 Evidence 확인` 아래 접힌 타임라인·실행 상세·JSON에서 원본과 ID를 확인한다.
7. 카드 아래 접힌 `이전 실행 불러오기`의 `실행 선택`으로 과거 run을 조회한다. 왼쪽 Sidebar는 사용하지 않는다. Replay는 Runtime을 다시 호출하지 않는다.
8. `A/B/C Evaluation`: Plugin Configuration에서 A의 네 Plugin OFF, B/C의 같은 네 Plugin ON 및 coordination OFF/ON을 먼저 설명한다.
9. Baseline 0.80 → Mechanism Demonstration 0.92의 B/C 비교 → 실제 report 표·PNG·표본 수·생성 시각 순서로 설명한다.

실행 결과, execution state / executed, output allowed, policy reason / version, cumulative risk, run_id / trace_id, Evidence Timeline / Raw JSON은 기존과 같이 조회할 수 있다. 합성 API_KEY 출력은 개발자 상세에 보존되지만 차단된 출력은 전달 영역에 표시하지 않는다.

## Plugin 화면의 데이터 출처

- `Architecture only / Current code`: Live의 Enabled와 coordination은 현재 `make_security_factory` / `PolicyConfig` 기본값을 조회한 구조 설명이다. Guard 평가나 Tool 실행은 하지 않는다. 선택한 과거 run의 활성 설정이 저장되어 있다는 뜻이 아니다.
- Evaluation의 A/B/C 구성은 실제 condition YAML과 PluginManager registry에서 읽는다. 변경되거나 별도 정책으로 생성한 report의 과거 구성까지 보증하지 않으므로 report의 policy_version과 metadata도 확인한다.
- `Stored Evidence`: Guard 이름, stage, 판정, risk, latency, 최종 cumulative risk / policy_version / reason, execution 결과는 조회된 이벤트에서 읽는다. 현재 UI 구간에 기록이 없으면 Ready로 표시하며 미실행으로 확정하지 않는다.
- `Evidence Replay`: `st.fragment(run_every=0.4)`로 UI만 갱신한다. SQLite 조회 순서대로 모든 이벤트를 재생하고, PluginManager dispatch 같은 가상 이벤트를 만들지 않는다. Runtime에 sleep을 넣지 않는다. 전체 목록은 `Replay 이벤트 목록`에서 확인한다.
- 단계 카드는 실제 매칭 이벤트가 있을 때만 현재 / 완료 / 재생 대기로 강조한다. 기록이 없는 Guard는 `결과 기록 없음`이며 미실행으로 단정하지 않는다. 반복 검사 기록도 유지한다. 누적 위험도는 저장 SecurityDecision이 재생된 이후에만 접힌 판정 근거에 표시한다.
- Tool calls / output delivered는 완료된 Runtime 반환값·실행 요약이며 Replay의 중간 이벤트로 위장하지 않는다. 최종 Runtime Status도 보존한다.
- 선택 run의 coordination mode와 STANDARD → STRICT 전환은 Evidence에 없으므로 확인 불가다. Linked 동작 설명과 현재 코드의 ON 표시는 구조 설명으로 구분한다.
- 0.92 B/C 비교는 저장 summary의 ASR / Block Rate / 표본 수만 사용한다. 개별 ATTACK WARN / BLOCK은 summary에 없어 표시하지 않는다.

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

## Plugin presentation QA (2026-10-27)

작업 branch: `feat/plugin-runtime-presentation`, base: `35ab29f3af936f268728cdfd1f1f5f9e76c2d413` (PR #20 merge). 이번 변경은 commit / push / merge하지 않았다.

| 검사 | 결과 |
|---|---|
| `uv sync --frozen --group demo` | 성공 |
| `uv run --group demo pytest -q` | 259 passed |
| `uv run --group demo ruff check .` | All checks passed |
| `git diff --check` | 통과 |
| 실제 Scenario 1 / 2 / 3 | ALLOW·Tool 1·출력 허용 / BLOCK·Tool 0·출력 차단 / BLOCK·Tool 1·출력 차단 |
| Evidence | 세 시나리오 run_id / trace_id 일치, Runtime errors 없음 |
| Replay | Reset·Next·자동 진행·종료·전체 결과·run 변경 초기화 통과; 추가 Runtime 호출 없음; 저장 Evidence 불변 |
| 빈 상태 / 오류 | 실행 전 구조 표시, report 없음, Evidence 없음 시 persistence OK 미표시, ERROR/TIMEOUT 빨간 오류 표시 통과 |
| Evaluation UI | PNG 없는 summary-only report 표시, B/C 비교, 실제 A/B/C Plugin 설정 검증 통과 |

새 공식 실험을 생성하거나 기존 360-trial report를 덮어쓰지 않았다. AppTest report 입력은 임시 test fixture이며 발표 데이터가 아니다. 브라우저 연결이 없어 실제 화면의 시각 검수와 자동 타이머의 브라우저 재생 리허설은 미완료다. AppTest는 UI 상태 진행과 결과 불변성을 검증했다.

변경 파일: `demo/dashboard.py`, `demo/plugin_view.py`, `demo/reports.py`, `tests/integration/test_plugin_dashboard.py`, 이 문서. Security / PluginManager / Guard / Runtime / Enforcement / Evidence schema / Evaluation metric / condition 정책 / threshold / Common schema / pyproject / lock은 변경하지 않았다.

판단: 자동 검증 기준으로 dev 반영 후보에 적합하다. 실제 발표 환경에서 화면 밀도, Replay 동작과 검증된 report 경로를 확인한 후 반영한다.

## PR #20 당시 QA 기록 (이력)

당시 기준 branch: `feat/presentation-dashboard`, base: `14c9ffec18dc4d9573354ebd11c47c944fb4ebdc` (PR #19 merge). 이후 사용자 승인으로 PR #20을 dev에 merge했다 (`35ab29f`). 아래 결과는 현재 Plugin presentation 변경 전의 이력이다.

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
