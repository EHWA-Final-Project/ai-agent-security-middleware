# Team Development Workflow

## Branches

- `main`: stable / release
- `dev`: team integration
- feature branches: each member's implementation branch

Recommended branches:

- `feat/security-core` — Fatin
- `feat/evidence-evaluation` — Wana
- `feat/runtime-enforcement` — 이지원
- `chore/platform-integration` — 오지송

Do not develop directly on `main` or `dev`.

## Local work migration

Existing local repositories should not be merged wholesale with unrelated Git history.

1. Clone this repository.
2. Checkout the latest `dev`.
3. Create your own branch from `dev`.
4. Move the implementation and tests you actually need.
5. Replace temporary duplicated common models with the agreed shared/common contracts.
6. Run local tests.
7. Open a PR to `dev`.

## Migration order

1. Fatin — repository skeleton / common baseline / Security Core
2. Wana — Evidence / Evaluation
3. 이지원 — Runtime / Enforcement
4. Cross-layer wiring and actual interface replacement
5. 오지송 — Thin API / CI / integration smoke / release QA

Fatin's baseline is first because the current Security Core already provides the common Enum / Schema / ID / Contract foundation that the other modules depend on.

## Contract rule

If a change affects a shared Enum, Schema, DTO, Protocol, Service signature, or public repository interface:

1. Update the Notion Interface Spec.
2. Review with affected Producer / Consumer.
3. Merge only after the contract is agreed.
4. Update Contract Tests together with the change.

## Pull request rule

Every PR should state:

- what changed;
- related Task / Interface Spec;
- test commands actually run;
- common contract impact;
- integration / blocker notes.

## Integration target

For the current Cross-layer Integration sprint, the minimum integrated path is:

`Runtime → Security Orchestrator → Enforcement → Evidence`

Required checks:

- shared `run_id` / `trace_id` propagation;
- benign path can complete;
- attack path can block;
- blocked Tool actual execution count is 0;
- timeout / error fallback is observable;
- Evidence can be stored and queried.

## CI

CI will be enabled after the common `pyproject.toml` and `uv.lock` from the baseline are merged into `dev`.

Initial intended gate:

```bash
uv sync --frozen
uv run ruff check .
uv run pytest -q
```

Integration smoke will be added after actual Runtime / Security / Evidence wiring is merged.
