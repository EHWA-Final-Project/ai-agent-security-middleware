from pydantic import BaseModel, Field
from schemas.evidence import EvaluationResult, SecurityEvent


class RunResultDTO(BaseModel):
    """Minimal run-level result returned to Thin Query."""

    run_id: str
    events: list[SecurityEvent] = Field(default_factory=list)


class TraceResultDTO(BaseModel):
    """Minimal trace-level Evidence result returned to Thin Query."""

    trace_id: str
    events: list[SecurityEvent] = Field(default_factory=list)


class MetricsDTO(BaseModel):
    """Minimal metrics response structure for P0.

    Full metric aggregation is implemented in the later Evaluation Pipeline.
    """

    experiment_condition: str | None = None
    total_runs: int = 0
    attack_scenarios: int = 0
    benign_scenarios: int = 0

    asr: float | None = None
    tsr: float | None = None
    fpr: float | None = None
    block_rate: float | None = None

    average_latency_ms: float | None = None
    p50_latency_ms: float | None = None
    p95_latency_ms: float | None = None

    policy_version: str | None = None


__all__ = [
    "EvaluationResult",
    "MetricsDTO",
    "RunResultDTO",
    "TraceResultDTO",
]