# Integration Checklist

Updated against the integrated P0 demo branch on 2026-10-08.

## Repository baseline

- [x] Private team repository created
- [x] `main` stable branch
- [x] `dev` integration branch
- [x] Python 3.12 pin
- [x] .gitignore
- [x] .env.example
- [x] .editorconfig
- [x] Pull Request template
- [x] Team workflow
- [x] Fatin common baseline merged into `dev`
- [x] `pyproject.toml` / `uv.lock` verified with `uv sync --frozen` in CI
- [x] CI enabled on the Platform demo PR

## Producer → Consumer integration

### Fatin → 이지원
- [x] RuntimeObservation actual import
- [x] Orchestrator entry point connected
- [x] SecurityDecision actual object connected
- [x] WARN / BLOCK / timeout contract verified

### Fatin → Wana
- [x] SecurityResult actual object connected
- [x] SecurityDecision actual object connected
- [x] Evidence fields compatible
- [x] Error / timeout evidence path verified

### 이지원 → Wana
- [x] RuntimeObservation evidence path connected
- [x] ExecutionResult actual object connected
- [x] RunStatus semantics verified
- [x] Tool failure semantics verified

### Wana → 오지송
- [x] Evidence query interface connected
- [x] Run / Trace result shape connected
- [x] Metrics DTO available
- [x] partial failure behavior covered by Runtime/Contract tests

> Full ASR / TSR / FPR and p50 / p95 aggregation is **not** complete yet.
> `GET /metrics` is explicitly exposed as a P0 placeholder for the later
> Evaluation Pipeline milestone.

### 이지원 → 오지송
- [x] Runtime service entry point connected
- [x] `POST /runs` call boundary implemented
- [x] result / error mapping exposed through the Thin API

## Cross-layer smoke

- [x] clean GitHub Actions checkout + `uv sync --frozen`
- [x] Ruff pass
- [x] Unit / Contract / Integration / E2E tests pass
- [x] Runtime → Security → Enforcement → Evidence connected
- [x] run_id / trace_id propagated end-to-end
- [x] BENIGN path ALLOW / EXECUTED
- [x] ATTACK path Context WARN → STRICT → Tool WARN → BLOCK
- [x] BLOCKed Tool execution count 0 verified in E2E
- [x] Guard TIMEOUT fail-closed covered by existing Contract test
- [x] Evidence stored and queryable by Run / Trace
- [x] Demo command and professor demo flow documented

## Current automated QA result

GitHub Actions · PR #14:

```text
uv run ruff check .
→ All checks passed!

uv run pytest -q
→ 123 passed, 1 warning
```

## Remaining after the P0 demo gate

- [ ] Move FastAPI / uvicorn / httpx into the frozen project dependency set
- [ ] A/B/C experiment harness: No Guard / Independent / Cross-layer
- [ ] P1 Adaptive Inspection
- [ ] ASR / TSR / FPR aggregation
- [ ] Average / p50 / p95 latency aggregation
- [ ] Replay / Regression pipeline
