"""Application composition owned by Platform / Integration.

This module wires existing Runtime, Security, Evidence, and Evaluation modules
without duplicating their core logic.
"""

from __future__ import annotations

import os
from pathlib import Path

from evaluation.models import MetricsDTO
from evaluation.query_service import EvidenceQueryService
from evidence.collector import EvidenceCollector
from evidence.sqlite_repository import SQLiteEvidenceRepository
from runtime.adapter import RuntimeAdapter
from runtime.composition import make_security_factory
from runtime.dto import RuntimeRequest
from runtime.mock_tools.tools import MockReadFile, MockSendEmail
from runtime.runner import RuntimeRunResult
from security.policy.config import PolicyConfig


class PlatformContainer:
    """Compose the P0 vertical slice for API/demo use."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        resolved_db = Path(
            db_path or os.getenv("EVIDENCE_DB_PATH", ".data/evidence.db")
        )
        resolved_db.parent.mkdir(parents=True, exist_ok=True)

        self.repository = SQLiteEvidenceRepository(resolved_db)
        self.evidence = EvidenceCollector(self.repository)
        self.query = EvidenceQueryService(self.repository)
        self.runtime = RuntimeAdapter()

        # P0 demo tools are intentionally local and side-effect free.
        self.read_file = MockReadFile(
            {
                "notes.txt": "Quarterly revenue increased by 12 percent.",
                "fixtures/safe.txt": "Synthetic safe document for BENIGN-001.",
            }
        )
        self.send_email = MockSendEmail()
        self.tools = {
            "read_file": self.read_file,
            "send_email": self.send_email,
        }

        # Cross-layer demo policy: allow Context WARN to propagate to the
        # Tool stage so STANDARD -> STRICT -> TOOL BLOCK is observable.
        self.policy = PolicyConfig(
            policy_version="demo-cross-layer-v1",
            strict_threshold=0.50,
            block_threshold=0.99,
        )

    def run(self, request: RuntimeRequest) -> RuntimeRunResult:
        return self.runtime.run(
            request,
            tools=self.tools,
            evidence=self.evidence,
            security_factory=make_security_factory(self.policy, self.evidence),
        )

    def metrics_snapshot(self) -> MetricsDTO:
        """P0 placeholder until the M4 aggregation pipeline is implemented."""
        return MetricsDTO(
            experiment_condition="P0_CROSS_LAYER_DEMO",
            policy_version=self.policy.policy_version,
        )
