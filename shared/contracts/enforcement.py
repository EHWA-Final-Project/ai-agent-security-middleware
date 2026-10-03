"""Owner (real implementation): 지원.
"""

from __future__ import annotations

from typing import Protocol

from schemas.runtime import ExecutionResult
from schemas.security import SecurityDecision


class EnforcementInterface(Protocol):

    def enforce(self, decision: SecurityDecision) -> ExecutionResult | None: ...
