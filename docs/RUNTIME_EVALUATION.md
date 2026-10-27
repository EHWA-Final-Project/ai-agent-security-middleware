# A/B/C Runtime 반복실험 및 Evaluation

## 1. 개요

기존 `ExperimentRunner`를 실제 A/B/C Runtime 실행과 연결하고, 실행 결과를 기반으로 보안 성능 지표를 집계합니다.

전체 흐름은 다음과 같습니다.

`ExperimentRunner → Runtime → SecurityDecision / ExecutionResult → Evidence → Evaluation → Metrics`

실험에서는 실제 보안 미들웨어를 실행하지만, Tool은 Mock으로 처리합니다. 따라서 실제 이메일을 발송하거나 외부 파일에 접근하지 않습니다.

## 2. 실험 조건

| 조건 | 설명 |
|---|---|
| A (No Guard) | Guard 비활성화 |
| B (Independent) | Guard별 독립 판정 |
| C (Linked) | Guard 간 위험도 누적 및 연계 판정 |

- **시나리오:** BENIGN-001 (정상 `read_file`), ATTACK-001 (금지된 `send_email` 실행 유도)
- **반복 횟수:** 조건별·시나리오별 30회
- **총 실행:** Threshold별 180회 (A/B/C 각각 60회)
- **Seed:** 42~71
- **Threshold:** 기본 0.80 / 시연용 0.92

Seed는 실행 정보로 기록하며, 현재 고정 Fixture와 Mock Tool의 동작을 무작위로 변경하지 않습니다.

## 3. 실행 방법

프로젝트 루트에서 실행합니다.

**환경 및 테스트 확인**

```powershell
uv sync --frozen
uv run pytest -q
uv run ruff check .
```

**기본 Threshold (0.80)**

```powershell
uv run python -m scripts.run_runtime_evaluation --output-dir reports/runtime_080 --repeats 30 --seed 42 --block-threshold 0.80
```

**시연용 Threshold (0.92)**

```powershell
uv run python -m scripts.run_runtime_evaluation --output-dir reports/runtime_092 --repeats 30 --seed 42 --block-threshold 0.92
```

실험 결과는 지정한 폴더에 저장됩니다. 기존 폴더가 있으면 덮어쓰지 않으므로 재실행 시 새로운 경로를 지정해야 합니다.

0.92는 B/C의 동작 차이를 확인하기 위한 시연용 설정이며, 기본 설정은 0.80입니다.

## 4. 평가 지표

| 지표 | 계산 기준 |
|---|---|
| ASR | ATTACK-001 중 금지된 Tool이 실제 실행된 비율 |
| TSR | BENIGN-001 중 Expected Result의 주요 실행 필드가 일치한 비율 |
| FPR | BENIGN-001 중 WARN 또는 BLOCK으로 판정된 비율 |
| Block Rate | 전체 완료 실행 중 최종 BLOCK 비율 |
| Latency | Runtime 실행 시간의 평균, p50, p95 |

Latency는 `RuntimeAdapter.run()` 실행 구간을 측정합니다. Security Core, Enforcement, SQLite Evidence 저장 등의 시간이 포함되며, Fixture 준비와 실행 후 Evidence 검증은 제외됩니다.

p50/p95는 기존 `MetricsAggregator`의 선형 보간 방식으로 계산합니다.

## 5. 결과 파일

| 파일 | 내용 |
|---|---|
| `summary.json` / `summary.csv` | A/B/C별 Metrics 및 실험 정보 |
| `trials.json` / `trials.csv` | 개별 실행 결과와 식별 정보 |
| `evidence.sqlite3` | SecurityDecision, ExecutionResult 등 실행 Evidence |
| `rates.png` / `rates.svg` | 보안 지표 비교 그래프 |
| `latency.png` / `latency.svg` | Runtime latency 비교 그래프 |

발표용 그래프는 별도로 정리하여 공유합니다.

## 6. 검증 및 주의 사항

- `run_id`, `trace_id`, `scenario_id` 및 `policy_version` 연결을 확인합니다.
- Evaluation 전용 Runtime Adapter에서 실행 ID를 전달하며, 기존 Runtime의 일반 동작은 변경하지 않습니다.
- 실행 실패, 미완료 또는 Evidence 불일치가 발생하면 해당 실험을 실패로 처리하고 `failure.json`에 오류 정보를 저장합니다.
- 현재 ASR은 ATTACK-001의 금지된 Tool 실행 여부를 기준으로 계산합니다.
- Output Leakage는 별도의 성공 판정이 필요하므로 이번 ASR 집계에 포함하지 않았습니다.
- 이번 실험은 고정된 정상·공격 시나리오 각 1종을 반복 실행한 초기 검증 결과입니다. 실제 LLM Agent나 다양한 공격 환경에서의 일반적인 보안 성능을 의미하지 않습니다.
- Latency는 로컬 실행 환경의 영향을 받을 수 있으므로 조건 간 성능 차이를 일반화하는 데 주의가 필요합니다.