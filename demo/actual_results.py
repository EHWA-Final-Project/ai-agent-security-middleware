"""Read-only joins over sanitized historical observations, never live execution."""

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "external_mcp_actual"
TABLES = (
    "trial_observations", "candidate_observations", "individual_guard_results",
    "model_tool_selections", "operational_metrics", "semantic_metrics",
    "matched_abcd_comparisons", "metric_definitions", "report_summary_ko", "summary",
)


def load_results(root=REPORT):
    root = Path(root)
    data = {name: json.loads((root / "dashboard" / f"{name}.json").read_text(encoding="utf-8"))
            for name in TABLES}
    data["configuration"] = json.loads((root / "experiment_configuration.json").read_text(encoding="utf-8"))
    validate_results(data)
    return data


def validate_results(data):
    """Reject inconsistent cross-table identities/counts rather than show success."""
    trials = data["trial_observations"]
    by_run = {t["run_id"]: t for t in trials}
    config = data["configuration"]
    if len(by_run) != len(trials) or len(trials) != config["planned_attempts"]:
        raise ValueError("Trial identity/count mismatch")
    if dict(Counter(t["status"] for t in trials)) != config["status_counts"]:
        raise ValueError("Execution status counts differ from provenance")
    if data["summary"]["status_counts"] != config["status_counts"]:
        raise ValueError("Summary status counts differ from observations")
    if sum(t["evidence_validated"] is True for t in trials) != config["evidence_validated"]:
        raise ValueError("Evidence validation count mismatch")
    pairs = {(t["sample_id"], t["condition"]) for t in trials}
    samples = {t["sample_id"] for t in trials}
    if len(samples) != config["mapped_samples"] or pairs != {(s, c) for s in samples for c in "ABCD"}:
        raise ValueError("Incomplete or duplicate A/B/C/D sample matrix")
    candidates = set()
    for row in data["candidate_observations"]:
        key = row["run_id"], row["candidate_id"]
        if key in candidates:
            raise ValueError("Duplicate candidate identity")
        candidates.add(key)
        if row["pre_execution_block"] is True and not (
            row["executed"] is False and row["sdk_call_count"] == 0
            and row["server_tool_execution_count"] == 0
        ):
            raise ValueError("Pre-execution BLOCK contradicts tool execution")
    for name in ("candidate_observations", "individual_guard_results", "model_tool_selections"):
        for row in data[name]:
            trial = by_run.get(row["run_id"])
            if trial is None or any(row[k] != trial[k] for k in ("sample_id", "condition", "dataset", "status")):
                raise ValueError(f"{name}: trial identity mismatch")
            if name == "individual_guard_results" and (row["run_id"], row["candidate_id"]) not in candidates:
                raise ValueError("Guard result without candidate")
    for name in ("operational_metrics", "semantic_metrics"):
        for row in data[name]:
            numerator, denominator, rate = row["numerator"], row["denominator"], row["rate"]
            if numerator is not None and denominator is not None and not 0 <= numerator <= denominator:
                raise ValueError(f"{name}: invalid numerator/denominator")
            if rate is not None and (not denominator or numerator is None or abs(rate - numerator / denominator) > 1e-9):
                raise ValueError(f"{name}: rate differs from counts")


def display(value):
    if value is None:
        return "알 수 없음 / N/A"
    if value is True:
        return "예"
    if value is False:
        return "아니오"
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    return value


def rows_for(data, name, run_id):
    return [row for row in data[name] if row["run_id"] == run_id]


def boundary(row):
    if row.get("pre_execution_block") is True:
        return "실행 전 BLOCK"
    if row.get("executed") is True and row.get("output_withheld") is True:
        return "EXECUTED + 출력 미전달"
    if row.get("executed") is True:
        return "EXECUTED"
    return "알 수 없음"
