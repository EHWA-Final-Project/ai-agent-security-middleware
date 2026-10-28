# 10/29 발표 실행 가이드

최종 발표 기준 branch는 **`dev`**다. Freeze candidate HEAD는 `6f2de1f3385d66d68ae9fa64047cd91c6b09a3e3`이며 PR #20–#23은 dev merge 완료다. `main` release merge는 발표 후 별도 판단한다.

프로젝트 핵심은 **Plugin-based AI Agent Security Middleware**이고 Dashboard는 실제 Runtime / Guard / Enforcement / Evidence / Evaluation을 보여주는 Presentation / Observability layer다.

## 환경과 실행

`pyproject.toml`, `uv.lock`, `demo/`가 존재하는 최신 `dev` repository root에서 실행한다. 발표 PC마다 clone / worktree 위치가 다르므로 특정 과거 worktree 이름이나 Windows 절대 경로에 의존하지 않는다. 먼저 아래 결과가 대상 root / `dev` / freeze candidate HEAD와 일치하는지 확인한다.

```powershell
git rev-parse --show-toplevel
git branch --show-current
git rev-parse HEAD
uv sync --frozen --group demo
uv run --group demo pytest -q
uv run --group demo ruff check .
uv run --group demo streamlit run demo/dashboard.py
```

`demo`는 별도 dependency group이다. 일반 `uv sync --frozen`만 실행하면 Streamlit이 설치되지 않거나 제거될 수 있으므로 시연은 반드시 `--group demo`로 실행한다. CLI는 `uv run python demo/cli.py`로 계속 사용할 수 있다.

Git Bash에서 root로 이동할 때는 `/` 경로를 사용하고 공백이 있는 경로는 따옴표로 감싼다. `Group demo is not defined`가 나오면 다른 저장소에서 실행하지 않았는지 root와 branch를 다시 확인한다. 실행 후 `http://localhost:8501`에 접속하며 종료는 `Ctrl+C`다.

## 클릭 순서와 확인 항목

1. `Plugin Execution Trace`에서 상단의 다섯 단계 안내와 세 시나리오 카드를 보여준다. 카드의 예상 결과와 실행 후 실제 결과를 구분한다.
2. `정상 요청` 카드의 `실행`: 큰 요약 카드에서 ALLOW, Tool 실행됨, Output 전달, Evidence 저장 확인을 보여준다. 실제 문서 출력은 `실행 상세 · 정책 / 출력 / 식별자`에서 확인한다.
3. `▶ 자동으로 흐름 보기`: 저장 이벤트를 자동 재생한다. `↺ 처음부터` → `→ 한 단계씩 보기`로 한 이벤트씩 진행할 수도 있다. `✓ 최종 결과 보기`는 최종 화면으로 돌아간다. 저장된 Evidence를 실행 순서대로 재생하며 실제 Runtime은 다시 실행하지 않는다.
4. `공격 시도 차단` 카드의 `실행`: BLOCK, Tool 미실행, 출력 차단을 확인한다. 새 run은 자동 선택되고 Replay도 해당 run 기준으로 초기화된다.
5. `실행 후 출력 차단` 카드의 `실행`: Tool 실행됨, 출력 차단을 확인한다. Replay의 Enforcement → OUTPUT Guard 순서는 저장 순서 그대로다.
6. 가로 파이프라인의 현재 단계와 실제 ALLOW / WARN / BLOCK을 설명한다. Plugin Manager는 별도 이벤트가 없는 구조 카드이며 재생 상태를 만들지 않는다. `Evidence · SQLite`에서 저장 count와 조회 상태를 확인한다. `⑤ 저장된 Evidence 확인` 아래 접힌 타임라인·실행 상세·JSON에서 원본과 ID를 확인한다.
7. 카드 아래 접힌 `이전 실행 불러오기`의 `실행 선택`으로 과거 run을 조회한다. 왼쪽 Sidebar는 사용하지 않는다. Replay는 Runtime을 다시 호출하지 않는다.
8. `A/B/C Evaluation`: Plugin Configuration에서 A = ALL OFF / Coordination N/A, B = 4 ON / OFF, C = 4 ON / ON을 먼저 설명한다. B/C는 같은 Plugin을 사용하며 coordination 방식이 다르다.
9. Baseline 0.80 → Mechanism Demonstration 0.92의 B/C 비교 → 실제 report 표·PNG·표본 수·생성 시각 순서로 설명한다.

실행 결과, execution state / executed, output allowed, policy reason / version, cumulative risk, run_id / trace_id, Evidence Timeline / Raw JSON은 기존과 같이 조회할 수 있다. 합성 API_KEY 출력은 개발자 상세에 보존되지만 차단된 출력은 전달 영역에 표시하지 않는다.

## Plugin 화면의 데이터 출처

- `Architecture only / Current code`: Live의 Enabled와 coordination은 현재 `make_security_factory` / `PolicyConfig` 기본값을 조회한 구조 설명이다. Guard 평가나 Tool 실행은 하지 않는다. 선택한 과거 run의 활성 설정이 저장되어 있다는 뜻이 아니다.
- Evaluation의 A/B/C 구성은 실제 condition YAML과 PluginManager registry에서 읽는다. 변경되거나 별도 정책으로 생성한 report의 과거 구성까지 보증하지 않으므로 report의 policy_version과 metadata도 확인한다.
- `Stored Evidence`: Guard 이름, stage, 판정, risk, latency, 최종 cumulative risk / policy_version / reason, execution 결과는 조회된 이벤트에서 읽는다. 해당 기록이 없으면 `결과 기록 없음`으로 표시하며 미실행으로 확정하지 않는다.
- `Evidence Replay`: `st.fragment(run_every=0.4)`로 UI만 갱신한다. SQLite 조회 순서대로 모든 이벤트를 재생하고, PluginManager dispatch 같은 가상 이벤트를 만들지 않는다. Runtime에 sleep을 넣지 않는다. 전체 목록은 `Replay 이벤트 목록`에서 확인한다.
- 단계 카드는 실제 매칭 이벤트가 있을 때만 현재 / 완료 / 재생 대기로 강조한다. 기록이 없는 Guard는 `결과 기록 없음`이며 미실행으로 단정하지 않는다. 반복 검사 기록도 유지한다. 누적 위험도는 저장 SecurityDecision이 재생된 이후에만 접힌 판정 근거에 표시한다.
- Tool calls / output delivered는 완료된 Runtime 반환값·실행 요약이며 Replay의 중간 이벤트로 위장하지 않는다. 최종 Runtime Status도 보존한다.
- 선택 run의 coordination mode와 STANDARD → STRICT 전환은 Evidence에 없으므로 확인 불가다. Linked 동작 설명과 현재 코드의 ON 표시는 구조 설명으로 구분한다.
- 0.92 B/C 비교는 저장 summary의 ASR / Block Rate / 표본 수만 사용한다. 개별 ATTACK WARN / BLOCK은 summary에 없어 표시하지 않는다.

## Evaluation report 배치

360-trial report는 Git repository에 commit하지 않는다. 발표 PC의 `reports/` 아래 검증된 threshold 0.80 report와 threshold 0.92 report를 각각 배치한다. 기본 탐색 대상은 하위 `summary.json`이다. 별도 위치라면 접힌 `발표 설정 / Report 경로` 안의 `Report directory`에 지정한다. 검증된 report 폴더를 그대로 배치하고 생성 시각·source commit·repeats·total trials를 확인한다. 임시 smoke 결과를 발표용 360-trial 결과로 대체하지 않는다.

동일 폴더의 `summary.csv`, `rates.png`, `latency.png`를 재사용한다. PNG가 없어도 summary 표는 표시된다. Report가 없거나 잘못된 JSON이면 안내를 표시하며 Live 탭은 계속 사용할 수 있다. 수치는 summary에서 읽으며 UI가 재계산하지 않는다. 비율은 0–1, latency는 ms이다.

발표는 검증된 report 배치를 기본으로 한다. 다음은 별도 재현이 필요할 때의 명령이며 이번 문서 정리에서는 실행하지 않는다. 출력 디렉터리는 존재하지 않아야 한다. 기존 검증 결과를 덮어쓰지 않는다.

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
- FastAPI thin boundary from PR #14 is deferred and excluded from the 10/29 presentation baseline. stale baseline, 구 0.99 정책, placeholder metrics, FastAPI / uvicorn / httpx 의존성을 그대로 가져오지 않는다. 현재 Streamlit Runtime / Evidence / Evaluation 경로가 발표 요구를 충족한다. PR #14는 close하지 않는다. [감사 기록](PLATFORM_API_AUDIT.md)을 참고한다.
- Windows sandbox의 uv cache / pytest 임시 디렉터리 권한 오류는 과거 정상 권한 재실행으로 분리해 확인했다. 권한 오류를 제품 실패나 성공으로 해석하지 않는다.
- 10/28에는 신규 개발 없이 이 순서로 리허설한다. 발표 전 두 탭, 세 버튼, report 경로와 생성 시각을 확인한다.

## 최종 QA / presentation freeze 상태

발표 baseline: **dev `6f2de1f3385d66d68ae9fa64047cd91c6b09a3e3`**. 아래는 문서 정리 전에 이미 확인된 최종 QA 기록이며, 이번 문서 전용 작업에서 새 공식 Evaluation을 생성하거나 테스트 로직을 바꾸지 않는다.

| 항목 | 최종 확인 상태 / 근거 |
|---|---|
| Frozen 환경 / 전체 테스트 | `uv sync --frozen --group demo` 성공, **261 passed** |
| Ruff / diff 검사 | All checks passed / `git diff --check` pass |
| 세 Runtime 시나리오 | 정상 ALLOW·Tool 1·출력 전달 / 실행 전 BLOCK·Tool 0 / 실행 후 Tool 1·출력 차단 |
| SQLite Evidence / ID | 실제 저장·run / trace 조회, run_id / trace_id 일치 |
| A/B/C → Runtime → Evidence → Evaluation / Metrics | 연결 검증 완료; ASR / TSR / FPR / Block Rate 및 mean / p50 / p95 latency |
| 360 Trial results | 팀 최종 QA 확인: baseline 0.80 / mechanism demonstration 0.92 각 180 trial; 검증 report 별도 배치 |
| ERROR-001 | Tool Guard timeout → fail-closed BLOCK / execution_state BLOCKED / Tool 0; Runtime E2E verified |
| Dashboard / Evidence Replay | AppTest 7개 포함; Replay 전후 Evidence 불변, Runtime 추가 호출 없음, 과거 run·report 조회 유지 |
| Runtime / Enforcement blocker | 추가 blocker 없음 |
| Freeze 판단 | 10/29 presentation freeze candidate |

ERROR-001 timeout 경로의 회귀 근거는 `tests/contract/test_runtime_connected.py::test_tool_guard_timeout_blocks_real_enforcement`다. SQLite / Evaluation / Replay의 근거 파일은 [Integration checklist](INTEGRATION_CHECKLIST.md)에 정리했다. Tool 실행 자체의 timeout / 취소와 프로세스 재시작을 넘는 exactly-once 보장은 완료 범위에 포함하지 않는다.

Replay 순서 조사에서는 기존 SQLite 8개 run 모두 `CREATED`가 처음, `COMPLETED`가 마지막이었다. repository 반환 순서도 일치했다. AppTest에서 초기 최종 화면은 `12/12 · COMPLETED`, 재생 첫 이벤트는 `1/12 · CREATED`였으며, 브라우저에서 보고된 `1/12 · COMPLETED` 현상은 재현되지 않아 원인을 확정하지 않았다. UI는 이벤트 번호·created_at·상태를 같은 저장 이벤트로 묶어 표시하고 Evidence를 재정렬하지 않는다.

자동 검증 완료와 발표 PC 준비는 구분한다. 실제 화면의 시각 검수·자동 재생 리허설 및 검증된 report 배치 여부는 발표 PC에서 최종 확인한다. dev 자동 CI gate는 미완료이며 로컬 검증을 원격 CI 통과로 표현하지 않는다. 이는 신규 Runtime / Enforcement blocker를 의미하지 않는다.

## 병합 이력

| PR | dev 반영 내용 |
|---|---|
| #20 | Runtime 시나리오 직접 실행 / report 탭 / 발표 QA 가이드 |
| #21 | Plugin 구조 / Cross-layer 설명 / 저장 Evidence Replay |
| #22 | 시나리오 중심 제품 데모 UI / 접힌 과거 실행·상세 |
| #23 | A Coordination N/A / 한국어 Replay 문구 / Report 경로 접힘 / 이벤트 표시 정합성 |

이전 feature / fix branch와 임시 smoke 디렉터리는 개발·검증 이력이며 현재 발표 실행 기준이 아니다. PR #20–#23은 이미 dev merge 완료다. 이번 작업은 문서 정합성만 정리하며 source / Dashboard / 테스트를 변경하거나 dev / main에 push·merge하지 않는다.
