"""Pinned inventory validation, fixture replay, and restricted single actual trials."""

import argparse
import asyncio
import importlib.metadata
import json
import math
import platform
import subprocess
from pathlib import Path
from time import perf_counter

from evidence.sqlite_repository import SQLiteEvidenceRepository

from .external_mcp_adapter import load_bipia_candidates, record_sha256, sha256
from .external_mcp_fixture import FixtureReplayBackend, fixture_policy
from .external_mcp_judges import judge_trial
from .external_mcp_plots import render_graphs
from .external_mcp_report import FIXTURE_LABEL, json_write, write_reports
from .external_mcp_runtime_backend import (
    RuntimeExecutionBackend,
    runtime_model_configuration,
    runtime_policy,
)
from .external_mcp_trial_runner import (
    ExternalMCPTrialRunner,
    TrialConfig,
    UnavailableConfiguration,
)
from .mcp_external_manifest import build_manifest
from .msb_mcp_adapter import load_msb_candidates

ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = ROOT / "benchmarks/bipia_mcp_candidate_manifest.json"
PROVENANCE = ROOT / "benchmarks/mcp_external_manifest.json"


def verify_inventory(cases, manifest, previous):
    """No additions, removals, substitutions or normalization of pinned source hashes."""
    regenerated = build_manifest(cases, previous)
    if manifest.get("selection_status") != "candidate_only" or manifest.get("selection_frozen") is not False:
        raise ValueError("this CLI requires the existing candidate-only inventory")
    if len(cases) != 12 or regenerated["counts"] != {
        "total": 12, "attack": 6, "benign": 6, "bipia": 10, "msb": 2, "pairs": 6,
    }:
        raise ValueError("expected unchanged 12-case external inventory")
    if regenerated["counts"] != manifest.get("counts") or regenerated["samples"] != manifest.get("samples"):
        raise ValueError("regenerated mapped-case hashes or provenance differ from tracked manifest")
    return regenerated


def load_verified_cases(dataset_root, candidate_manifest=CANDIDATE, provenance_manifest=PROVENANCE):
    candidate_manifest, provenance_manifest = Path(candidate_manifest), Path(provenance_manifest)
    # User-specified copies are accepted only when their bytes match the tracked inputs.
    if candidate_manifest.read_bytes() != CANDIDATE.read_bytes():
        raise ValueError("candidate manifest differs from repository candidate manifest")
    if provenance_manifest.read_bytes() != PROVENANCE.read_bytes():
        raise ValueError("provenance manifest differs from repository provenance manifest")
    for tracked in (CANDIDATE, PROVENANCE):
        committed = subprocess.run(
            ["git", "show", f"HEAD:{tracked.relative_to(ROOT).as_posix()}"], cwd=ROOT,
            capture_output=True, check=True, timeout=10,
        ).stdout
        if json.loads(committed.decode("utf-8-sig")) != json.loads(tracked.read_text(encoding="utf-8-sig")):
            raise ValueError("repository candidate/provenance manifest differs from tracked HEAD")
    manifest = json.loads(provenance_manifest.read_text(encoding="utf-8-sig"))
    cases = load_bipia_candidates(dataset_root, manifest_path=candidate_manifest)
    cases += load_msb_candidates(dataset_root)
    previous = (ROOT / "benchmarks/manifest.json").read_text(encoding="utf-8-sig")
    verify_inventory(cases, manifest, previous)
    return cases, manifest


def execution_revision():
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                            text=True, check=True, timeout=10)
    files = sorted(p for directory in ("src", "shared", "examples") for p in (ROOT / directory).rglob("*.py"))
    files += [ROOT / "scripts/run_external_mcp_evaluation.py", ROOT / "pyproject.toml", ROOT / "uv.lock"]
    files += sorted((ROOT / "src/security/policy").rglob("*.yaml"))
    files += sorted((ROOT / "src/security/policy").rglob("*.yml"))
    hashes = {p.relative_to(ROOT).as_posix(): sha256(p.read_bytes()) for p in files}
    digest = record_sha256(hashes)
    return f"{result.stdout.strip()}+evaluation-sha256:{digest}", digest


def parser():
    p = argparse.ArgumentParser(description="External MCP evaluation; actual execution requires one explicit sample and condition")
    p.add_argument("operation", choices=("validate", "fixture", "actual"))
    p.add_argument("--dataset-root", type=Path, required=True)
    p.add_argument("--candidate-manifest", type=Path, default=CANDIDATE)
    p.add_argument("--provenance-manifest", type=Path, default=PROVENANCE)
    p.add_argument("--conditions", nargs="+", choices=list("ABCD"), default=list("ABCD"))
    p.add_argument("--repeats", type=int, default=1)
    p.add_argument("--seed", type=lambda value: None if value.lower() == "none" else int(value), default=0)
    p.add_argument("--sample-id", help="Required exact sample ID for one actual trial only")
    p.add_argument("--pi-t01", choices=("off", "on"), default="off")
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--backend", choices=("mapping-only", "fixture-replay", "actual-agent"), required=True)
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--experiment-id", default="external-mcp-candidate-validation-v1")
    p.add_argument("--graphs", action="store_true")
    return p


def validate_options(args):
    expected = {"validate": "mapping-only", "fixture": "fixture-replay", "actual": "actual-agent"}
    if args.backend != expected[args.operation]:
        raise ValueError("operation/backend mismatch; no execution fallback is allowed")
    if args.repeats < 1 or not math.isfinite(args.timeout) or args.timeout <= 0:
        raise ValueError("repeats and finite timeout must be positive")
    if len(args.conditions) != len(set(args.conditions)):
        raise ValueError("conditions must be unique")
    if not args.experiment_id.strip():
        raise ValueError("experiment ID must not be empty")
    output = args.output_dir.resolve()
    if output == ROOT or ROOT in output.parents:
        raise ValueError("external evaluation output must be outside the repository")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("output directory must be new or empty")
    if args.operation == "actual":
        if not args.sample_id or not args.sample_id.strip():
            raise UnavailableConfiguration("actual requires --sample-id; no fixture substitution performed")
        if len(args.conditions) != 1 or args.repeats != 1:
            raise UnavailableConfiguration("actual requires exactly one condition and repeats=1; batch disabled")
        if args.seed is not None:
            raise UnavailableConfiguration("actual requires --seed none; Runtime cannot apply a generation seed")
    elif args.sample_id is not None:
        raise ValueError("--sample-id is only supported for restricted actual execution")


async def fixture_trials(cases, manifest, args, revision):
    backend = FixtureReplayBackend()
    runner = ExternalMCPTrialRunner(backend=backend, policy_resolver=fixture_policy, evidence_lookup=backend.events.get)
    rows = []
    for case in sorted(cases, key=lambda c: c["sample_id"]):
        for condition in sorted(args.conditions):
            for repeat in range(args.repeats):
                cfg = TrialConfig(
                    experiment_id=args.experiment_id, condition=condition, repeat=repeat, seed=args.seed,
                    model=None, execution_scope="fixture_execution", output_injection_scan=args.pi_t01 == "on",
                    timeout_seconds=args.timeout, code_revision=revision,
                    policy_comparison_key="simulated-fixture-common-settings-v1",
                )
                result = await runner.run(case, manifest, cfg)
                # Do not publish variable harness wall time as policy/Agent latency.
                result.latency_ms = None
                result.latency_scope = "fixture_replay_timing_not_measured"
                result = judge_trial(result, case, backend.events.get)
                rows.append(result)
    return rows, backend


def actual_trial(case, manifest, args, revision, config):
    """Run once, persist private facts before reporting, and never retry failures."""
    try:
        model = runtime_model_configuration()
    except (ValueError, RuntimeError) as exc:
        raise UnavailableConfiguration("Runtime model environment is unavailable or invalid") from exc
    if (not math.isfinite(model["request_timeout_seconds"])
            or model["request_timeout_seconds"] <= 0 or model["max_tokens"] <= 0):
        raise UnavailableConfiguration("Runtime request timeout and token limit must be positive and finite")
    cfg = TrialConfig(
        experiment_id=args.experiment_id, condition=args.conditions[0], repeat=0,
        seed=None, model=model, execution_scope="actual_llm_mcp", output_injection_scan=args.pi_t01 == "on",
        timeout_seconds=args.timeout, code_revision=revision,
    )
    runtime_policy(cfg)  # Fail unsupported configuration before any output or model call.
    private = args.output_dir / "private"
    backend = RuntimeExecutionBackend(private / "attempts")
    runner = ExternalMCPTrialRunner(
        backend=backend, policy_resolver=runtime_policy, evidence_lookup=backend.events.get,
    )
    private.mkdir(parents=True, mode=0o700)
    started = perf_counter()
    trial = asyncio.run(runner.run(case, manifest, cfg))
    # Preserve returned sidecars even if subsequent judging/reporting fails.
    json_write(private / "trial_sidecar.json", trial.model_dump(mode="json"))
    json_write(private / "runtime_identity_mappings.json", [
        binding.model_dump(mode="json") for binding in trial.observation.runtime_bindings
    ])
    # Replay index copies original IDs/payloads; original per-attempt DBs stay in place.
    repository = SQLiteEvidenceRepository(private / "evidence.sqlite3")
    for event in backend.events.values():
        repository.save_event(event)
    trial = judge_trial(trial, case, backend.events.get)
    json_write(private / "trial_sidecar.json", trial.model_dump(mode="json"))
    config.update(
        policy_configuration_status="runtime_configuration_preflight_verified",
        selected_sample_id=case["sample_id"], verified_inventory_count=12,
    )
    bundles = write_reports([trial], backend.events.get, args.output_dir / "reports", execution_config=config)
    graph_count = sum(len(render_graphs(bundle, backend.events.get)) for bundle in bundles) if args.graphs else 0
    result = {
        "execution_scope": "actual_llm_mcp", "status": trial.observation.run_status,
        "verified_inventory_cases": 12, "sample_id": case["sample_id"], "trials": 1,
        "condition": trial.condition, "run_id": trial.run_id, "trace_id": trial.trace_id,
        "evidence_validated": trial.evidence_validated, "backend_latency_ms": trial.latency_ms,
        "elapsed_seconds": perf_counter() - started, "graph_files": graph_count,
        # Returned responses/candidate counters are not a complete invocation audit.
        "actual_model_calls": None, "actual_sdk_calls": None,
        "exit_status": 0 if trial.observation.run_status == "completed" and trial.evidence_validated else 1,
    }
    json_write(args.output_dir / "execution_summary.json", result)
    return result


def run(args):
    validate_options(args)
    cases, manifest = load_verified_cases(args.dataset_root, args.candidate_manifest, args.provenance_manifest)
    # Full pinned inventory verification happens above, even for a single sample.
    selected = None
    if args.operation == "actual":
        matches = [case for case in cases if case["sample_id"] == args.sample_id]
        if len(matches) != 1:
            raise ValueError("sample ID must match exactly one verified inventory entry")
        selected = matches[0]
    revision, code_hash = execution_revision()
    config = {
        "conditions": sorted(args.conditions), "repeats": args.repeats, "seed": args.seed,
        "pi_t01": args.pi_t01, "backend": args.backend, "timeout_seconds": args.timeout,
        "experiment_id": args.experiment_id, "execution_code_sha256": code_hash,
        "candidate_manifest_file_sha256": sha256(args.candidate_manifest.read_bytes()),
        "provenance_manifest_file_sha256": sha256(args.provenance_manifest.read_bytes()),
        "policy_configuration_status": "simulated_fixture_only" if args.operation == "fixture" else "not_executed",
        "graphs": args.graphs,
        "python_version": platform.python_version(),
        "package_versions": {name: importlib.metadata.version(name) for name in ("pydantic", "matplotlib", "mcp")},
    }
    if args.operation == "actual":
        config["package_versions"].update({
            name: importlib.metadata.version(name) for name in ("anyio", "PyYAML")
        })
        return actual_trial(selected, manifest, args, revision, config)
    if args.operation == "validate":
        args.output_dir.mkdir(parents=True, exist_ok=True)
        json_write(args.output_dir / "run_metadata.json", {
            "schema_version": "external-mcp-mapping-validation-v1", "execution_scope": "mapping_only",
            "counts": manifest["counts"], "manifest_sha256": record_sha256(manifest),
            "code_revision": revision, "selection_status": "candidate_only", "selection_frozen": False,
            "raw_content_exported": False, "source_integrity": "exact bytes; pinned CRLF acquisition",
            "execution_config": config,
        })
        return {"status": "mapping_verified", "cases": len(cases), "actual_execution": False}
    rows, backend = asyncio.run(fixture_trials(cases, manifest, args, revision))
    bundles = write_reports(rows, backend.events.get, args.output_dir, execution_config=config)
    private = args.output_dir / "private"
    private.mkdir()
    repository = SQLiteEvidenceRepository(private / "fixture_evidence.sqlite3")
    for event in backend.events.values():
        repository.save_event(event)
    graph_count = 0
    for bundle in bundles:
        if args.graphs:
            graph_count += len(render_graphs(bundle, backend.events.get))
    return {"label": FIXTURE_LABEL, "cases": len(cases), "trials": len(rows),
            "completed": sum(t.observation.run_status == "completed" for t in rows),
            "conditions": sorted(args.conditions), "graph_files": graph_count,
            "actual_model_calls": 0, "actual_sdk_calls": 0, "policy_configuration": "simulated_fixture_only"}


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    try:
        result = run(args)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        # Fixed validation messages contain no raw dataset text; decoder errors may.
        message = str(exc) if type(exc) in (ValueError, UnavailableConfiguration) else type(exc).__name__
        p.exit(2, f"External MCP validation failed: {message}\n")
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return result.get("exit_status", 0)


if __name__ == "__main__":
    raise SystemExit(main())
