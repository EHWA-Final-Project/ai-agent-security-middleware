"""Thin FastAPI boundary for the professor demo and Platform integration."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse

from runtime.dto import RuntimeRequest

from .container import PlatformContainer
from .demo import DEMO_HTML


def create_app(
    container: PlatformContainer | None = None,
    *,
    db_path: str | Path | None = None,
) -> FastAPI:
    app = FastAPI(
        title="AI Agent Security Middleware · P0 Demo",
        version="0.1.0",
        description=(
            "Thin Platform boundary over Runtime → Security → Enforcement → "
            "Evidence. Core security logic remains in the owned modules."
        ),
    )

    services = container or PlatformContainer(db_path=db_path)
    app.state.container = services

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse(url="/demo")

    @app.get("/demo", response_class=HTMLResponse, include_in_schema=False)
    def demo() -> HTMLResponse:
        return HTMLResponse(DEMO_HTML)

    @app.get("/health", tags=["platform"])
    def health() -> dict:
        return {
            "status": "ok",
            "policy_version": services.policy.policy_version,
            "components": {
                "runtime": "ready",
                "security": "ready",
                "evidence": "ready",
            },
        }

    @app.post("/runs", tags=["runtime"])
    def create_run(request: RuntimeRequest) -> dict:
        result = services.run(request)
        return result.model_dump(mode="json")

    @app.get("/runs/{run_id}", tags=["evidence"])
    def get_run(run_id: str) -> dict:
        result = services.query.get_run_result(run_id)
        if not result.events:
            raise HTTPException(status_code=404, detail="run_id not found")
        return result.model_dump(mode="json")

    @app.get("/traces/{trace_id}", tags=["evidence"])
    def get_trace(trace_id: str) -> dict:
        result = services.query.get_trace_result(trace_id)
        if not result.events:
            raise HTTPException(status_code=404, detail="trace_id not found")
        return result.model_dump(mode="json")

    @app.get("/metrics", tags=["evaluation"])
    def get_metrics() -> dict:
        return {
            "aggregation_status": "P0_PLACEHOLDER",
            "message": (
                "ASR/TSR/FPR and p50/p95 aggregation is scheduled for the "
                "Evaluation Pipeline milestone."
            ),
            "metrics": services.metrics_snapshot().model_dump(mode="json"),
        }

    return app


app = create_app()
