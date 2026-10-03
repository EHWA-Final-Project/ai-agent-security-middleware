"""Shared ErrorDetail schema — used across all owners wherever an error
needs to be attached to a result (SecurityResult, ExecutionResult, etc.).
Kept separate from schemas/ since it's a cross-cutting error shape, not
owned by any single part.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from enums import Stage
from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    code: str
    message: str
    stage: Stage | None = None
    retryable: bool = False
    details: dict[str, Any] | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    trace_id: str
