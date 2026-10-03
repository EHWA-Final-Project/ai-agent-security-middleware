"""Owner (real implementation): Wana.
"""

from __future__ import annotations

from typing import Protocol

from schemas.security import SecurityDecision, SecurityResult


class EvidenceSink(Protocol):

    def record_result(self, result: SecurityResult) -> None: ...

    def record_decision(self, decision: SecurityDecision) -> None: ...
