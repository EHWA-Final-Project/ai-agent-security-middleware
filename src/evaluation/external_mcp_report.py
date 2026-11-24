"""Metadata-only JSON/CSV handoff; no sidecar dumps or raw Evidence export."""

import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from .external_mcp_adapter import record_sha256, sha256
from .external_mcp_comparison import compare_cd
from .external_mcp_metrics import aggregate_external

SCHEMA_VERSION = "external-mcp-report-v1"
FIXTURE_LABEL = "FIXTURE VALIDATION — NOT ACTUAL MODEL EVALUATION"
MODEL_FIELDS = {"provider", "name", "model", "version", "temperature", "top_p", "max_tokens", "seed"}
CD_FIELDS = (
    "schema_version", "sample_id", "pair_id", "scenario_id", "dataset", "attack_family", "repeat",
    "execution_scope", "c_run_id", "d_run_id", "c_trace_id", "d_trace_id", "unmatched_run_id",
    "c_policy_version", "d_policy_version", "policy_comparison_key", "model_configuration",
    "output_injection_scan", "manifest_sha256", "comparison_eligible", "regression_candidate",
    "review_reasons", "c_decision", "d_decision", "decision_summary", "comparable_security_boundaries",
    "boundary_transitions", "verified_attack_outcome_regression", "attack_outcome_comparison_exclusion_reason",
    "latency_d_minus_c_ms", "latency_scope", "latency_exclusion_reason",
)
# Only machine reason codes are shareable. Manual prose is represented by a digest.
REASON_CODES = {"actual_model_execution_required", "actual_execution_required", "mapping_only", "not_benign", "different_classification", "independent_judgment_missing", "judgment_identity_mismatch", "judgment_evidence_missing", "payload_exposure_or_selection_trace_missing", "final_delivery_or_reviewed_withholding_missing", "not_observed", "not_applicable", "not_applicable_benign", "reference_answer_unsupported", "missing_or_ambiguous_final_model_response", "final_response_delivery_unverified", "exact_reference_answer", "explicit_model_refusal", "nonmatching_answer_requires_review", "reversal_semantics_require_review", "reversal_indistinguishable_from_legitimate_answer", "actual_delivered_response_required", "exact_reviewed_characters_reversal", "exact_reviewed_words_reversal", "legitimate_answer_or_explicit_refusal", "incorrect_or_ambiguous_answer_not_attack_success", "unambiguous_reversal_is_not_reference_answer", "model_candidate_trace_incomplete", "model_requested_simulated_transfer", "complete_trace_has_no_target_request", "verified_unauthorized_simulated_transfer", "complete_simulated_sink_audit_no_transfer", "simulated_transfer_or_complete_sink_audit_missing", "reviewed_complete_pre_exposure_failure", "guard_or_candidate_trace_incomplete", "guard_observation_missing", "guard_decision_not_separated_from_tool_policy", "guard_results_incomplete_or_failed", "guard_snapshot_not_backed_by_evidence", "guard_alert_rule_evidence_missing", "guard_warning_observation_missing", "guard_warning_rule_evidence_missing", "contradictory_guard_warning_observation", "tool_execution_not_observed", "output_boundary_unknown", "output_block_not_confirmed", "output_guard_observation_missing", "pre_tool_boundary_unknown", "pre_tool_block_not_confirmed", "sdk_trace_unknown", "no_candidate_observation", "latency_missing", "evidence_not_validated", "policy_configuration_unknown", "model_configuration_unknown", "not_external_adapted", "run_evidence_missing", "candidate_evidence_missing", "snapshot_identity_mismatch", "snapshot_policy_mismatch", "security_snapshot_evidence_missing", "sdk_evidence_missing", "sdk_invocation_evidence_mismatch", "evidence_missing_or_mismatched", "error_or_timeout_diagnostics", "actual_trial_candidate_not_model_observed", "fixture_cannot_claim_model_selection", "ambiguous_duplicate_pair", "missing_condition", "common_policy_or_experiment_identity_unknown", "decision_snapshot_missing", "comparable_boundary_block_relaxation", "different_or_unknown_actions_inputs_or_stages", "outcome_regression_not_attributable_to_adaptive_policy", "incomparable_classification_or_judging_rules", "missing_or_different_latency_scope"}


def safe_reason(value):
    if value is None or value in REASON_CODES:
        return value
    if value in {f"status:{s}" for s in ("completed", "timeout", "error", "incomplete", "unknown")}:
        return value
    if value in {f"inconsistent_{s}" for s in (
        "policy_comparison_key", "policy_enabled", "output_injection_scan", "seed",
        "mapped_case_sha256", "manifest_sha256", "code_revision", "backend_id", "classification",
        "timeout_seconds", "pair_id",
    )}:
        return value
    return "redacted_reason_sha256:" + sha256(str(value).encode())


def safe_model(model):
    return {k: v for k, v in (model or {}).items()
            if k in MODEL_FIELDS and (v is None or type(v) in (str, bool, int, float))}


def _reason_counts(counts):
    safe = Counter()
    for reason, count in counts.items():
        safe[safe_reason(reason)] += count
    return dict(sorted(safe.items()))


def json_write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n",
                          encoding="utf-8")


def csv_write(path, rows, fields):
    with Path(path).open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            encoded = {}
            for key in fields:
                value = row.get(key)
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)
                elif isinstance(value, bool):
                    value = "true" if value else "false"
                # Spreadsheet formula injection must not execute identifier text.
                if isinstance(value, str) and re.match(r"^[\s]*[=+@-]", value):
                    value = "'" + value
                encoded[key] = value
            writer.writerow(encoded)


def trial_row(t):
    obs = t.observation
    candidates = obs.candidates
    outcomes = obs.semantic_outcomes
    row = {key: getattr(t, key) for key in (
        "run_id", "trace_id", "sample_id", "pair_id", "scenario_id", "classification", "condition",
        "repeat", "seed", "policy_version", "policy_enabled", "output_injection_scan", "execution_scope",
        "backend_id", "manifest_sha256", "mapped_case_sha256", "code_revision", "experiment_id",
        "policy_comparison_key", "timeout_seconds", "evidence_validated", "latency_ms", "latency_scope",
    )}
    row.update(
        schema_version=SCHEMA_VERSION, dataset=t.provenance["dataset_id"], attack_family=t.provenance["attack_id"],
        model_configuration=safe_model(t.model), model_configuration_sha256=record_sha256(t.model or {}),
        previous_attack_hash_overlap=t.provenance.get("previous_attack_hash_overlap"),
        run_status=obs.run_status, candidate_count=len(candidates),
        guard_decisions=[c.guard_decision for c in candidates],
        tool_policy_decisions=[c.tool_policy_decision for c in candidates],
        prevention_sources=[c.prevention_sources for c in candidates],
        pre_tool_block=[c.pre_tool_block for c in candidates],
        post_tool_output_block=[c.post_tool_output_block for c in candidates],
        output_delivered=obs.output_delivered,
        sdk_call_counts=None if obs.sdk_calls is None else {
            method: sum(c.method == method for c in obs.sdk_calls)
            for method in ("tools/list", "tools/call", "resources/read")
        },
        evidence_refs=sorted(set(obs.evidence_refs or []) | {
            ref for c in candidates for ref in (c.evidence_refs or [])
        }),
    )
    for name in ("attack", "task", "attempted_action"):
        judgment = getattr(outcomes, name) if outcomes else None
        row[f"{name}_outcome"] = judgment.value if judgment else None
        row[f"{name}_reason"] = safe_reason(judgment.reason) if judgment else "independent_judgment_missing"
        row[f"{name}_judge_version"] = judgment.judge_version if judgment else None
        row[f"{name}_evidence_refs"] = judgment.evidence_refs if judgment else []
    return row


def _cd_rows(comparison, indexed):
    rows = []
    for pair in comparison["pairs"]:
        c, d = indexed[pair["c_run_id"]], indexed[pair["d_run_id"]]
        row = {**pair, "schema_version": SCHEMA_VERSION, "pair_id": c.pair_id, "scenario_id": c.scenario_id,
               "dataset": c.provenance["dataset_id"], "attack_family": c.provenance["attack_id"],
               "c_trace_id": c.trace_id, "d_trace_id": d.trace_id,
               "comparison_eligible": "c_decision" in pair,
               "regression_candidate": "c_decision" in pair and bool(pair.get("review_reasons") or
                   pair.get("c_decision") != pair.get("d_decision") or
                   pair.get("verified_attack_outcome_regression")),
               "model_configuration": safe_model(c.model), "output_injection_scan": c.output_injection_scan,
               "manifest_sha256": c.manifest_sha256, "policy_comparison_key": c.policy_comparison_key}
        row["review_reasons"] = [safe_reason(reason) for reason in pair["review_reasons"]]
        row["attack_outcome_comparison_exclusion_reason"] = safe_reason(
            pair.get("attack_outcome_comparison_exclusion_reason")
        )
        rows.append(row)
    for missing in comparison["unmatched"]:
        for run_id in missing["run_ids"]:
            t = indexed[run_id]
            rows.append({"schema_version": SCHEMA_VERSION, "sample_id": t.sample_id, "pair_id": t.pair_id,
                         "scenario_id": t.scenario_id, "execution_scope": t.execution_scope,
                         "unmatched_run_id": run_id, "comparison_eligible": False,
                         "review_reasons": [safe_reason(missing["reason"])]})
    return rows


def write_reports(trials, evidence_lookup, output_dir, *, execution_config=None):
    """One six-file bundle per scope. Existing output directories are never overwritten."""
    root = Path(output_dir)
    if root.exists() and any(root.iterdir()):
        raise ValueError("report output directory must be empty")
    if not trials:
        raise ValueError("reporting requires trial observations")
    grouped = defaultdict(list)
    for trial in trials:
        grouped[trial.execution_scope].append(trial)
    bundles = []
    for scope, rows in sorted(grouped.items()):
        rows.sort(key=lambda t: (t.sample_id, t.condition, t.repeat, t.run_id))
        metrics = aggregate_external(rows, evidence_lookup)
        for group in metrics["groups"]:
            for metric in group["rates"].values():
                for field in ("exclusion_reasons", "excluded_trials_without_units"):
                    metric[field] = _reason_counts(metric[field])
            group["latency_exclusion_reasons"] = _reason_counts(group["latency_exclusion_reasons"])
        metrics["groups"].sort(key=lambda g: json.dumps(g["group"], sort_keys=True))
        comparison = compare_cd(rows, evidence_lookup)
        cd_rows = _cd_rows(comparison, {t.run_id: t for t in rows})
        comparison["pairs"] = [row for row in cd_rows if "c_run_id" in row]
        trial_rows = [trial_row(t) for t in rows]
        metric_rows = [{**group["group"], "schema_version": SCHEMA_VERSION, "metric": name, **metric}
                       for group in metrics["groups"] for name, metric in sorted(group["rates"].items())]
        config = execution_config or {}
        metadata = {
            "schema_version": SCHEMA_VERSION, "execution_scope": scope,
            "label": FIXTURE_LABEL if scope == "fixture_execution" else scope,
            "selection_status": "candidate_only", "selection_frozen": False,
            "official_benchmark_score": False, "unseen_holdout_claim": False,
            "raw_content_exported": False, "csv_null": "empty cell", "csv_nested_values": "JSON",
            "total_trials": len(rows), "unique_samples": len({t.sample_id for t in rows}),
            "code_revisions": sorted({t.code_revision for t in rows}),
            "manifest_sha256": sorted({t.manifest_sha256 for t in rows}),
            "execution_config": {k: config[k] for k in (
                "conditions", "repeats", "seed", "pi_t01", "backend", "timeout_seconds",
                "experiment_id", "execution_code_sha256", "candidate_manifest_file_sha256",
                "provenance_manifest_file_sha256", "policy_configuration_status", "graphs",
                "python_version", "package_versions",
            ) if k in config},
            "model_configurations": [safe_model(rows[0].model)] if len({record_sha256(t.model or {}) for t in rows}) == 1
                                    else [safe_model(t.model) for t in rows],
            "files": ["run_metadata.json", "trial_summary.csv", "metrics_summary.json",
                      "metrics_summary.csv", "cd_comparison.json", "cd_comparison.csv"],
        }
        destination = root / scope
        destination.mkdir(parents=True)
        json_write(destination / "run_metadata.json", metadata)
        csv_write(destination / "trial_summary.csv", trial_rows, list(trial_rows[0]))
        json_write(destination / "metrics_summary.json", metrics)
        csv_write(destination / "metrics_summary.csv", metric_rows,
                  sorted({key for row in metric_rows for key in row}))
        json_write(destination / "cd_comparison.json", comparison)
        csv_write(destination / "cd_comparison.csv", cd_rows, CD_FIELDS)
        bundles.append({"directory": destination, "metadata": metadata, "metrics": metrics,
                        "comparison": comparison, "trials": rows})
    return bundles
