# Integration Checklist

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
- [ ] Fatin common baseline merged
- [ ] `pyproject.toml` / `uv.lock` verified from clean clone
- [ ] CI enabled

## Producer → Consumer integration

### Fatin → 이지원
- [ ] RuntimeObservation actual import
- [ ] Orchestrator entry point agreed
- [ ] SecurityDecision actual object
- [ ] WARN / BLOCK / timeout contract verified

### Fatin → Wana
- [ ] SecurityResult actual object
- [ ] SecurityDecision actual object
- [ ] Evidence fields compatible
- [ ] Error / timeout evidence compatible

### 이지원 → Wana
- [ ] RuntimeObservation evidence path
- [ ] ExecutionResult actual object
- [ ] RunStatus semantics
- [ ] Tool failure semantics

### Wana → 오지송
- [ ] Evidence query interface
- [ ] Run / Trace result shape
- [ ] Metrics DTO
- [ ] partial failure behavior

### 이지원 → 오지송
- [ ] Runtime service entry point
- [ ] POST /runs call boundary
- [ ] result / error mapping

## Cross-layer smoke

- [ ] clean clone + `uv sync --frozen`
- [ ] Ruff pass
- [ ] Unit / Contract tests pass
- [ ] Runtime → Security → Enforcement → Evidence connected
- [ ] run_id / trace_id propagated end-to-end
- [ ] BENIGN path ALLOW / EXECUTED
- [ ] ATTACK path BLOCK / tool execution count 0
- [ ] Guard TIMEOUT fail-closed
- [ ] Evidence stored and queryable
- [ ] Demo command documented
