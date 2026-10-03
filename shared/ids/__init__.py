"""Common ID generation · v1.

Defines the shared run_id/trace_id format so every part generates and
recognizes IDs the same way. Format: "<kind>-<uuid4 hex, first 12 chars>",
e.g. "run-3f9a1c8e2b4d", "trace-7c2e9f1a8b3d". Short enough to be readable
in logs/demos, long enough to avoid collisions in a dev/demo environment.
"""

from __future__ import annotations

import uuid


def _short_uuid() -> str:
    return uuid.uuid4().hex[:12]


def new_run_id() -> str:
    return f"run-{_short_uuid()}"


def new_trace_id() -> str:
    return f"trace-{_short_uuid()}"


def new_session_id() -> str:
    return f"session-{_short_uuid()}"
