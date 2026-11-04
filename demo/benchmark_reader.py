"""Read-only Holdout presentation adapter; never runs or re-verifies trials."""

import hashlib
import json
import math
from pathlib import Path

THRESHOLDS = (0.70, 0.75, 0.80, 0.85, 0.90, 0.92, 0.95, 0.98)
METRICS = {
    "ASR": ("attack_tool_execution", "n_attack"),
    "pre_tool_block": ("pre_tool_block", "n_attack"),
    "TSR_read": ("completion_read", "n_benign_read"),
    "FPR_read(WARN|BLOCK)": ("fpr_read_warn_block", "n_benign_read"),
    "FPR_read(BLOCK)": ("fpr_read_block", "n_benign_read"),
    "FPR_send(WARN|BLOCK)": ("fpr_send_warn_block", "n_benign_send"),
    "FPR_send(BLOCK)": ("fpr_send_block", "n_benign_send"),
}


def read_json(path):
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise TypeError(f"{Path(path).name}: expected JSON object")
    return value


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def number(value, *, count=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("expected numeric value")
    if not math.isfinite(value) or value < 0:
        raise ValueError("expected finite nonnegative value")
    if count and (not isinstance(value, int)):
        raise ValueError("expected integer count")
    return value


def cell_key(row):
    mode = row["condition"]
    threshold = row["threshold"]
    if mode not in ("A", "B", "C"):
        raise ValueError("invalid condition")
    if mode == "A":
        if threshold not in (None, ""):
            raise ValueError("A threshold must be null or empty")
        return mode, None
    # The raw verification contract explicitly uses strings for thresholds.
    if isinstance(threshold, str):
        if not threshold.strip():
            raise ValueError("missing threshold")
        threshold = float(threshold)
    number(threshold)
    if threshold not in THRESHOLDS:
        raise ValueError("unsupported threshold")
    return mode, threshold


def validate_sweep(rows):
    if not isinstance(rows, list):
        raise TypeError("sweep must be a list")
    indexed = {}
    for row in rows:
        if not isinstance(row, dict):
            raise TypeError("cell must be an object")
        key = cell_key(row)
        if key in indexed:
            raise ValueError("duplicate condition/threshold")
        for field in ("n_attack", "n_benign_read", "n_benign_send"):
            number(row[field], count=True)
        for field, (_, denominator) in METRICS.items():
            rate = row[field]
            if row[denominator] == 0:
                if rate is not None:
                    raise ValueError("zero denominator requires null rate")
            elif number(rate) > 1:
                raise ValueError("rate outside [0,1]")
        for kind in ("read", "send"):
            warn_block, block = (
                row[f"FPR_{kind}(WARN|BLOCK)"],
                row[f"FPR_{kind}(BLOCK)"],
            )
            if warn_block is not None and block > warn_block:
                raise ValueError("BLOCK exceeds WARN|BLOCK")
        indexed[key] = row
    expected = {("A", None)} | {(m, t) for m in ("B", "C") for t in THRESHOLDS}
    if set(indexed) != expected:
        raise ValueError("expected A baseline and eight thresholds each for B/C")
    return indexed


def load_holdout(directory):
    """Return explicit missing/invalid/insufficient states, with no invented results.

    Hashes are local byte identities, not proof of original execution. Optional
    raw metadata is compared to supplied summaries, never treated as live evidence.
    """
    root = Path(directory)
    result = {
        "status": "결과 없음",
        "errors": [],
        "warnings": [],
        "hashes": {},
        "data": None,
        "raw": None,
        "rows": [],
        "runtime_execution_verified": False,
    }
    path = root / "holdout_results.json"
    if not path.is_file():
        return result
    try:
        data = read_json(path)
        if data["kind"] != "benchmark_evaluation" or data["split"] != "holdout":
            raise ValueError("expected benchmark_evaluation / holdout")
        for field in (
            "run",
            "data",
            "headline_block_threshold",
            "tool_policy",
            "sweep_default",
            "sweep_with_tool_policy",
            "c_block_cause",
            "notes",
        ):
            if field not in data:
                raise ValueError(f"missing {field}")
        if not isinstance(data["run"], dict) or not isinstance(data["data"], dict):
            raise TypeError("run/data must be objects")
        if number(data["headline_block_threshold"]) != 0.80:
            raise ValueError("headline threshold must be 0.80")
        sweeps = {
            name: validate_sweep(data[field])
            for name, field in (
                ("default", "sweep_default"),
                ("tool_policy", "sweep_with_tool_policy"),
            )
        }
        result["data"] = data
        result["hashes"][path.name] = sha256(path)
        result["status"] = "검증 불충분"
        for name in (
            "run_record_holdout.json",
            "raw_verification.json",
            "figures/aggregate_validation.json",
        ):
            candidate = root / name
            if candidate.is_file():
                result["hashes"][name] = sha256(candidate)
            else:
                result["warnings"].append(f"missing {name}")
        raw_path = root / "raw_verification.json"
        if raw_path.is_file():
            raw = read_json(raw_path)
            if (
                raw["schema_version"] != "holdout-raw-verification-v1"
                or raw["status"] != "raw_arithmetic_verified"
                or raw["runtime_execution_verified"] is not False
            ):
                raise ValueError("unsupported raw verification state")
            totals = raw["mismatch_totals"]
            if not isinstance(totals, dict) or not totals:
                raise ValueError("missing mismatch totals")
            if any(number(v, count=True) != 0 for v in totals.values()):
                raise ValueError("raw verification contains mismatches")
            inputs = raw["input_sha256"]
            if not isinstance(inputs, dict):
                raise ValueError("input_sha256 must be an object")
            for required in ("holdout_results.json", "run_record_holdout.json"):
                if (
                    inputs.get(required) != result["hashes"].get(required)
                    or required not in result["hashes"]
                ):
                    raise ValueError(f"missing or mismatched input SHA256: {required}")
            for name, summary in sweeps.items():
                cells = raw["sweeps"][name]["cells"]
                indexed = {cell_key(cell): cell for cell in cells}
                if len(indexed) != len(cells) or set(indexed) != set(summary):
                    raise ValueError("raw cell coverage differs")
                for key, row in summary.items():
                    cell = indexed[key]
                    for count in ("n_attack", "n_benign_read", "n_benign_send"):
                        if number(cell[count], count=True) != row[count]:
                            raise ValueError("raw population differs")
                    for source, (metric, denominator) in METRICS.items():
                        n = number(cell[metric + "_numerator"], count=True)
                        d = number(cell[metric + "_denominator"], count=True)
                        if d != row[denominator] or n > d:
                            raise ValueError("raw numerator/denominator inconsistent")
                        rate = None if d == 0 else n / d
                        if rate is not None and abs(rate - row[source]) > 1e-12:
                            raise ValueError("raw rate differs from summary")
            result["raw"] = raw
            result["status"] = "제공 산술 검증 메타데이터 일치"
        for name, indexed in sweeps.items():
            for (mode, threshold), cell in indexed.items():
                for source, (metric, denominator) in METRICS.items():
                    raw_cells = (
                        result["raw"]["sweeps"][name]["cells"] if result["raw"] else []
                    )
                    raw_cell = next(
                        (c for c in raw_cells if cell_key(c) == (mode, threshold)), {}
                    )
                    result["rows"].append(
                        {
                            "policy": name,
                            "condition": mode,
                            "threshold": threshold,
                            "metric": metric,
                            "rate": cell[source],
                            "numerator": raw_cell.get(metric + "_numerator"),
                            "denominator": cell[denominator],
                        }
                    )
    except (OSError, ValueError, KeyError, TypeError, OverflowError) as exc:
        result.update(status="스키마 불일치", data=None, raw=None, rows=[])
        result["errors"].append(str(exc))
    return result
