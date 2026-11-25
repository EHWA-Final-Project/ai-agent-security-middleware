"""Generate metadata-only provenance for external MCP evaluation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .external_mcp_adapter import (
    load_bipia_candidates,
    record_sha256,
)
from .msb_mcp_adapter import load_msb_candidates

MANIFEST_VERSION = "mcp-external-pilot-v1"

ROOT = Path(__file__).resolve().parents[2]

BIPIA_MANIFEST = ROOT / "benchmarks" / "bipia_mcp_candidate_manifest.json"

OUTPUT_PATH = ROOT / "benchmarks" / "mcp_external_manifest.json"

BIPIA_PROVENANCE_FIELDS = (
    "dataset_id",
    "revision",
    "split",
    "source_url",
    "context_file",
    "context_line",
    "context_record_sha256",
    "context_file_sha256",
    "context_license",
    "attack_file",
    "attack_index",
    "attack_category",
    "attack_text_sha256",
    "attack_file_sha256",
    "attack_license",
    "original_id_type",
)

MSB_PROVENANCE_FIELDS = (
    "dataset_id",
    "revision",
    "source_url",
    "license_spdx",
    "original_attack_type",
    "source_template_id",
    "source_objective_id",
    "source_agent_id",
    "source_task_index",
    "source_files",
    "source_template_sha256",
    "source_objective_sha256",
    "source_task_sha256",
    "original_id_type",
    "benchmark_scope",
)


def case_metadata(
    case: dict[str, Any],
    previous_manifest: str,
) -> dict[str, Any]:
    """Export identifiers and hashes, never raw benchmark text."""
    dataset = case["dataset_id"]
    source = case["provenance"]

    if dataset == "bipia":
        fields = BIPIA_PROVENANCE_FIELDS
    elif dataset == "msb":
        fields = MSB_PROVENANCE_FIELDS
    else:
        raise ValueError("Unsupported dataset")

    provenance = {key: source[key] for key in fields}

    overlap = None

    if dataset == "bipia":
        overlap = source["attack_text_sha256"].lower() in previous_manifest.lower()

    return {
        "sample_id": case["sample_id"],
        "scenario_id": case["scenario_id"],
        "pair_id": case["pair_id"],
        "dataset_id": dataset,
        "source_type": case["source_type"],
        "classification": case["classification"],
        "attack_id": case["attack_id"],
        "entry_surface": case["entry_surface"],
        "adapter_version": case["adapter_version"],
        "execution_scope": "mapping_only",
        "provenance": provenance,
        "transformation": case["transformation"],
        "previous_attack_hash_overlap": overlap,
        "mapped_case_sha256": record_sha256(case),
        "review_status": "pending",
        "judge_status": "pending",
        "execution_status": "not_executed",
    }


def build_manifest(
    cases: list[dict[str, Any]],
    previous_manifest: str,
) -> dict[str, Any]:
    """Build a reproducible inventory without observed results."""
    ids = [case["sample_id"] for case in cases]

    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate external sample IDs")

    pairs = {}

    for case in cases:
        pairs.setdefault(case["pair_id"], []).append(case["classification"])

    for classifications in pairs.values():
        if sorted(classifications) != ["attack", "benign"]:
            raise ValueError("Invalid attack/benign pair")

    return {
        "manifest_version": MANIFEST_VERSION,
        "experiment_kind": "external_adapted_agent_mcp",
        "selection_status": "candidate_only",
        "selection_frozen": False,
        "acquired_on": "2026-11-24",
        "acquisition_timezone": "Asia/Seoul",
        "official_benchmark_score": False,
        "unseen_holdout_claim": False,
        "raw_data_policy": (
            "Keep raw sources and text-bearing evidence outside the public repository."
        ),
        "planned_conditions": ["A", "B", "C", "D"],
        "planned_repeats": 1,
        "policy_configuration_status": "pending_team_agreement",
        "counts": {
            "total": len(cases),
            "attack": sum(c["classification"] == "attack" for c in cases),
            "benign": sum(c["classification"] == "benign" for c in cases),
            "bipia": sum(c["dataset_id"] == "bipia" for c in cases),
            "msb": sum(c["dataset_id"] == "msb" for c in cases),
            "pairs": len(pairs),
        },
        "samples": [case_metadata(case, previous_manifest) for case in cases],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset-root", required=True, type=Path)
    args = parser.parse_args()

    cases = load_bipia_candidates(
        args.dataset_root,
        manifest_path=BIPIA_MANIFEST,
    )

    cases += load_msb_candidates(args.dataset_root)

    previous = (ROOT / "benchmarks" / "manifest.json").read_text(encoding="utf-8-sig")

    manifest = build_manifest(cases, previous)

    OUTPUT_PATH.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print("=== EXTERNAL MCP PROVENANCE ===")
    print(json.dumps(manifest["counts"], indent=2))
    print("Unique sample IDs: VERIFIED")
    print("Matched pairs: VERIFIED")
    print("Raw benchmark text: NOT EXPORTED")
    print("Selection status: CANDIDATE ONLY")
    print("Actual execution: NOT EXECUTED")
    print("Manifest:", OUTPUT_PATH)


if __name__ == "__main__":
    main()
