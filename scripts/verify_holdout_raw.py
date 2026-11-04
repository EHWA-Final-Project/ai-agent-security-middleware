"""Recalculate frozen Holdout CSV evidence without running any experiment.

Run from the repository with python -m scripts.verify_holdout_raw --source ZIP
--raw-dir DIR --output NEW_DIR [--existing-figures DIR] [--package NEW.zip].
Inputs are read-only; packaging validates finalized report and figure hashes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src"), str(ROOT / "shared")]

from evaluation.handoff_audit import aggregate_trials, compare_summary
from scripts.plot_holdout_aggregates import (
    CAUSE_COUNTS,
    OPTIONAL_RAW,
    THRESHOLDS,
    json_bytes,
    key,
    load_files,
    number,
    parse_csv,
    parse_json,
    verify,
    write_validation_metadata,
)
from scripts.plot_holdout_aggregates import (
    generate as generate_figures,
)

TRIAL_TYPES = {"direct", "indirect", "benign_read", "benign_send"}
SCORES = ("input_score", "context_score", "tool_score", "output_score")
CAUSES = {
    "cumulative_risk",
    "strict_warn_escalation",
    "independent_score",
    "guard_block",
    "critical_rule",
    "other",
}


def sha256(blob):
    return hashlib.sha256(blob).hexdigest()


def canonical(rows):
    """Normalize CSV and JSON threshold representations for the shared auditor."""
    return [
        dict(row, threshold="" if key(row)[1] is None else str(key(row)[1]))
        for row in rows
    ]


def validate_trials(rows):
    if not rows:
        raise ValueError("Empty trials")
    required = {
        "trial_type",
        "sample_id",
        "source",
        "condition",
        "threshold",
        "decision",
        "tool_executed",
        "output_allowed",
        "block_stage",
        "block_cause",
        "final_risk",
        *SCORES,
    }
    for row in rows:
        if not required <= row.keys():
            raise ValueError("Missing trial fields")
        if not row["sample_id"] or row["trial_type"] not in TRIAL_TYPES:
            raise ValueError("Invalid trial identity/type")
        if row.get("split", "holdout") != "holdout":
            raise ValueError("Trial split is not holdout")
        for field in ("final_risk", *SCORES):
            if row[field] != "" and not 0 <= number(row[field]) <= 1:
                raise ValueError("Invalid trial score")
        if row["block_stage"]:
            if row["block_cause"] not in CAUSES:
                raise ValueError("Missing or unknown block cause")
        elif row["block_cause"]:
            raise ValueError("Block cause on unblocked trial")


def recalculate_causes(rows):
    result = []
    for threshold in THRESHOLDS:
        attack = [
            r
            for r in rows
            if key(r) == ("C", threshold) and r["trial_type"] in {"direct", "indirect"}
        ]
        blocked = [r for r in attack if r["block_stage"] == "pre_tool"]
        counts = Counter(r["block_cause"] for r in blocked)
        cumulative = counts["cumulative_risk"]
        strict = counts["strict_warn_escalation"]
        result.append(
            {
                "threshold": threshold,
                "cause_source": "block_cause",
                "n_attack": len(attack),
                "n_pre_tool_block": len(blocked),
                "cumulative_risk": cumulative,
                "strict_warn_escalation": strict,
                "guard_block_or_other": len(blocked) - cumulative - strict,
                "single_guard_ge_thr": sum(
                    any(r[f] != "" and number(r[f]) >= threshold for f in SCORES)
                    for r in blocked
                ),
            }
        )
    return result


def guard_metrics(rows, threshold):
    required = {
        "sample_id",
        "dataset",
        "subset",
        "label",
        "guard",
        "split",
        "risk_score",
        "decision",
    }
    grouped = defaultdict(list)
    identities = set()
    for row in rows:
        if not required <= row.keys():
            raise ValueError("Missing Guard fields")
        if not row["sample_id"] or row["sample_id"] in identities:
            raise ValueError("Duplicate or empty Guard identity")
        identities.add(row["sample_id"])
        if row["split"] != "holdout" or row["label"] not in {"attack", "benign"}:
            raise ValueError("Invalid Guard split/label")
        score = number(row["risk_score"])
        if not 0 <= score <= 1 or row["decision"] not in {"ALLOW", "WARN", "BLOCK"}:
            raise ValueError("Invalid Guard score/decision")
        if (score >= threshold) != (row["decision"] != "ALLOW"):
            raise ValueError("Guard score and detection decision disagree")
        grouped[tuple(row[f] for f in ("dataset", "subset", "label", "guard"))].append(
            row
        )
    groups = []
    for identity, group in sorted(grouped.items()):
        flagged = sum(number(r["risk_score"]) >= threshold for r in group)
        groups.append(
            dict(
                zip(("dataset", "subset", "label", "guard"), identity),
                n=len(group),
                flagged=flagged,
                rate=flagged / len(group),
            )
        )
    totals = {}
    for label in ("attack", "benign"):
        group = [r for r in rows if r["label"] == label]
        flagged = sum(number(r["risk_score"]) >= threshold for r in group)
        totals[label] = {
            "n": len(group),
            "flagged": flagged,
            "rate": flagged / len(group) if group else None,
        }
    return {
        "records": len(rows),
        "unique_ids": len(identities),
        "detection_threshold": threshold,
        "groups": groups,
        "totals": totals,
        "false_positive_ids": sorted(
            r["sample_id"]
            for r in rows
            if r["label"] == "benign" and r["decision"] != "ALLOW"
        ),
    }


def verify_raw(files):
    missing = set(OPTIONAL_RAW) - files.keys()
    if missing:
        raise ValueError(f"Missing raw files: {sorted(missing)}")
    results, summary, policy, causes, audit = verify(files)
    record = parse_json(files["run_record_holdout.json"])
    mismatches = {
        "summary_csv": [],
        "summary_json": [],
        "causes_csv": [],
        "causes_json": [],
        "guard_metadata": [],
    }
    sweeps = {}
    populations = []
    raw_default = None
    for name, csv_rows, json_name, raw_name in (
        ("default", summary, "sweep_default", OPTIONAL_RAW[0]),
        ("tool_policy", policy, "sweep_with_tool_policy", OPTIONAL_RAW[1]),
    ):
        rows = canonical(parse_csv(files[raw_name]))
        validate_trials(rows)
        cells = aggregate_trials(rows)
        for target, supplied in (
            ("summary_csv", csv_rows),
            ("summary_json", results[json_name]),
        ):
            mismatches[target].extend(
                dict(m, sweep=name) for m in compare_summary(cells, canonical(supplied))
            )
        baseline = [r for r in rows if r["condition"] == "A"]
        population = {(r["trial_type"], r["sample_id"]) for r in baseline}
        populations.append(population)
        sweeps[name] = {
            "rows": len(rows),
            "conditions": len(cells),
            "unique_sample_ids": len({r["sample_id"] for r in rows}),
            "scenario_trials_per_condition": len(baseline),
            "trial_types_per_condition": dict(
                sorted(Counter(r["trial_type"] for r in baseline).items())
            ),
            "cells": cells,
            "missing_runtime_identity_fields": sorted(
                {"run_id", "trace_id"} - rows[0].keys()
            ),
        }
        if name == "default":
            raw_default = rows
    if populations[0] != populations[1]:
        raise ValueError("Default and ToolPolicy populations differ")
    computed_causes = recalculate_causes(raw_default)
    for target, supplied in (
        ("causes_csv", causes),
        ("causes_json", results["c_block_cause"]),
    ):
        indexed = {number(r["threshold"]): r for r in supplied}
        for row in computed_causes:
            for field in CAUSE_COUNTS:
                expected = number(indexed[row["threshold"]][field])
                if row[field] != expected:
                    mismatches[target].append(
                        {
                            "threshold": row["threshold"],
                            "field": field,
                            "reported": expected,
                            "recomputed": row[field],
                        }
                    )
    guards = parse_csv(files[OPTIONAL_RAW[2]])
    guard_report = guard_metrics(
        guards, number(record["policy"]["strict_threshold_default"])
    )
    guard_ids = {r["sample_id"] for r in guards}
    sweep_ids = {identity[1] for identity in populations[0]}
    if not sweep_ids <= guard_ids:
        raise ValueError("Sweep IDs missing from Guard records")
    id_hash = sha256("\n".join(sorted(guard_ids)).encode())
    guard_report["sorted_ids_sha256"] = id_hash
    for field, actual in (
        ("n_samples_in_split", len(guards)),
        ("split_sample_ids_sha256", id_hash),
    ):
        if record["data"].get(field) != actual:
            mismatches["guard_metadata"].append(
                {
                    "field": field,
                    "recomputed": actual,
                    "reported": record["data"].get(field),
                }
            )
    omitted = Counter(
        (r["dataset"], r["subset"]) for r in guards if r["sample_id"] not in sweep_ids
    )
    types_by_id = defaultdict(list)
    for kind, identity in sorted(populations[0]):
        types_by_id[identity].append(kind)
    reused = Counter(
        tuple(sorted(kinds)) for kinds in types_by_id.values() if len(kinds) > 1
    )
    totals = {name: len(values) for name, values in mismatches.items()}
    return {
        "schema_version": "holdout-raw-verification-v1",
        "status": "raw_arithmetic_verified"
        if not any(totals.values())
        else "mismatches_found",
        "runtime_execution_verified": False,
        "input_sha256": audit["input_sha256"],
        "run_record_hashes_matched": audit["run_record_hashes_matched"],
        "sweeps": sweeps,
        "c_causes": computed_causes,
        "guards": guard_report,
        "mismatch_totals": totals,
        "mismatches": mismatches,
        "population_mapping": {
            "guard_samples": len(guard_ids),
            "unique_sweep_sample_ids": len(sweep_ids),
            "scenario_trials_per_condition": len(populations[0]),
            "guard_only_groups": [
                {"dataset": k[0], "subset": k[1], "n": n}
                for k, n in sorted(omitted.items())
            ],
            "reused_sample_scenarios": [
                {"trial_types": list(k), "n_ids": n} for k, n in sorted(reused.items())
            ],
            "explanation": "Guard rows count unique samples. Sweeps omit Guard-only IDs and reuse some IDs across distinct scenarios; trial identity is condition, threshold, trial_type, sample_id.",
        },
        "limitations": [
            "Offline arithmetic verification only: trial CSVs have no run_id/trace_id; real Runtime execution and Evidence linkage are not verified.",
            "Hashes establish consistency with the supplied record, not independent provenance or authenticity. Source datasets, frozen rules and original split construction were not revalidated.",
            "No experiment was rerun or retuned. Single supplied run; no confidence intervals.",
            "Attack execution is an experiment-supplied forbidden tool call, not real-model attack success. ToolPolicy suppression is a configuration effect, not Guard detection.",
            "Guard detection is risk_score >= recorded strict threshold, checked against non-ALLOW decisions; no separate supplied Guard aggregate table exists.",
            "Guard-only question IDs are absent as sweep sample_id values; their possible use as supporting scenario text cannot be established from these CSVs.",
            "Figures generated by this verifier carry a raw-arithmetic-verified footer; this does not certify original Runtime execution or Evidence linkage.",
        ],
    }


def generate(source, raw_dir, output, existing_figures=None):
    if output.exists():
        raise FileExistsError("Use a NEW output directory")
    files = load_files(source)
    for name in OPTIONAL_RAW:
        blob = (raw_dir / name).read_bytes()
        if name in files and files[name] != blob:
            raise ValueError(f"Conflicting raw inputs: {name}")
        files[name] = blob
    report = verify_raw(files)
    report["source_archive_sha256"] = (
        sha256(source.read_bytes()) if source.is_file() else None
    )
    report["implementation_sha256"] = {
        str(path.relative_to(ROOT)): sha256(path.read_bytes())
        for path in (
            Path(__file__),
            ROOT / "src/evaluation/handoff_audit.py",
            ROOT / "scripts/plot_holdout_aggregates.py",
        )
    }
    output.mkdir(parents=True, exist_ok=False)
    if report["status"] == "raw_arithmetic_verified":
        figures = generate_figures(
            source, output / "figures", raw_verification=report, _defer_metadata=True
        )
        report["figure_sha256"] = figures["figure_sha256"]
        report["figure_environment"] = figures["generator"]
        differences = []
        if existing_figures is not None:
            for name, digest in report["figure_sha256"].items():
                path = existing_figures / name
                if not path.is_file() or sha256(path.read_bytes()) != digest:
                    differences.append(name)
        report["existing_figures_checked"] = existing_figures is not None
        report["existing_figure_byte_mismatches"] = differences
        report["mismatch_totals"]["existing_figure_bytes"] = len(differences)
        if differences:
            report["status"] = "figure_bytes_differ"
    report_path = output / "raw_verification.json"
    report_path.write_bytes(json_bytes(report))
    if report["status"] == "raw_arithmetic_verified":
        write_validation_metadata(output / "figures", figures, report_path)
    return report


def package_outputs(output, destination):
    """Package only a finalized, internally consistent report and its figures."""
    import zipfile

    if destination.exists():
        raise FileExistsError("Use a NEW package path")
    raw_path = output / "raw_verification.json"
    metadata_path = output / "figures/aggregate_validation.json"
    raw = parse_json(raw_path.read_bytes())
    metadata = parse_json(metadata_path.read_bytes())
    if (
        raw.get("status") != "raw_arithmetic_verified"
        or metadata.get("status") != raw["status"]
        or raw.get("runtime_execution_verified") is not False
        or metadata.get("runtime_execution_verified") is not False
        or any(raw["mismatch_totals"].values())
        or metadata.get("raw_verification_report") != "../raw_verification.json"
        or metadata.get("raw_verification_report_sha256")
        != sha256(raw_path.read_bytes())
        or metadata.get("figure_sha256") != raw.get("figure_sha256")
        or metadata.get("input_sha256") != raw.get("input_sha256")
        or metadata.get("figure_verification_status") != raw["status"]
        or metadata.get("raw_verification_hash_scope") != "exact_file_bytes"
        or metadata.get("missing_raw_files") != []
        or metadata.get("raw_trial_recalculation_performed") is not True
    ):
        raise ValueError("Inconsistent package verification metadata")
    paths = [raw_path, metadata_path]
    expected = {
        f"holdout_{name}.{extension}"
        for name in (
            "attack_tool_execution",
            "benign_outcomes",
            "tool_policy",
            "c_block_causes",
        )
        for extension in ("png", "svg")
    }
    if set(raw["figure_sha256"]) != expected:
        raise ValueError("Expected exactly eight approved figure filenames")
    for name, digest in sorted(raw["figure_sha256"].items()):
        path = output / "figures" / name
        if sha256(path.read_bytes()) != digest:
            raise ValueError(f"Figure hash mismatch: {name}")
        paths.append(path)
    # Explicit whitelist excludes stale reports, temporary files and input datasets.
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(paths):
            member = zipfile.ZipInfo(
                path.relative_to(output).as_posix(), (1980, 1, 1, 0, 0, 0)
            )
            member.compress_type = zipfile.ZIP_DEFLATED
            member.external_attr = 0o100644 << 16
            archive.writestr(member, path.read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("source", "raw-dir", "output"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--existing-figures", type=Path)
    parser.add_argument(
        "--package", type=Path, help="Optional new deterministic ZIP path"
    )
    args = parser.parse_args()
    try:
        if args.package and args.package.exists():
            raise FileExistsError("Use a NEW package path")
        report = generate(args.source, args.raw_dir, args.output, args.existing_figures)
        if args.package and report["status"] == "raw_arithmetic_verified":
            package_outputs(args.output, args.package)
    except (ValueError, OSError, KeyError) as exc:
        parser.exit(2, f"error: {exc}\n")
    print(
        json.dumps(
            {"status": report["status"], "mismatch_totals": report["mismatch_totals"]}
        )
    )
    if report["status"] != "raw_arithmetic_verified":
        parser.exit(1)


if __name__ == "__main__":
    main()
