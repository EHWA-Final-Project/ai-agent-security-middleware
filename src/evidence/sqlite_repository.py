import json
import sqlite3
from contextlib import closing
from pathlib import Path

from enums import Stage
from schemas.evidence import SecurityEvent

from .repository import EvidenceRepository


class SQLiteEvidenceRepository(EvidenceRepository):
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    trace_id TEXT NOT NULL,
                    scenario_id TEXT,
                    event_type TEXT NOT NULL,
                    stage TEXT,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_security_events_run_id "
                "ON security_events(run_id)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_security_events_trace_id "
                "ON security_events(trace_id)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_security_events_scenario_id "
                "ON security_events(scenario_id)"
            )

    def save_event(self, event: SecurityEvent) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO security_events (
                    event_id, run_id, trace_id, scenario_id,
                    event_type, stage, payload, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.run_id,
                    event.trace_id,
                    event.scenario_id,
                    event.event_type,
                    event.stage.value if event.stage else None,
                    json.dumps(event.payload, ensure_ascii=False, default=str),
                    event.created_at.isoformat(),
                ),
            )

    def _query(self, field: str, value: str) -> list[SecurityEvent]:
        allowed_fields = {"run_id", "trace_id", "scenario_id"}
        if field not in allowed_fields:
            raise ValueError(f"Unsupported query field: {field}")

        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                f"SELECT * FROM security_events WHERE {field} = ? ORDER BY created_at ASC",
                (value,),
            ).fetchall()

        events: list[SecurityEvent] = []
        for row in rows:
            events.append(
                SecurityEvent(
                    event_id=row["event_id"],
                    run_id=row["run_id"],
                    trace_id=row["trace_id"],
                    scenario_id=row["scenario_id"],
                    event_type=row["event_type"],
                    stage=Stage(row["stage"]) if row["stage"] else None,
                    payload=json.loads(row["payload"]),
                    created_at=row["created_at"],
                )
            )
        return events

    def list_events_by_run(self, run_id: str) -> list[SecurityEvent]:
        return self._query("run_id", run_id)

    def list_events_by_trace(self, trace_id: str) -> list[SecurityEvent]:
        return self._query("trace_id", trace_id)

    def list_events_by_scenario(self, scenario_id: str) -> list[SecurityEvent]:
        return self._query("scenario_id", scenario_id)
