"""Run validated A/B/C middleware experiments with in-memory mock tools.

Usage: uv run python -m scripts.run_runtime_evaluation --output-dir reports/runtime_080
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.metadata
import json
import platform
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
for _path in (ROOT_DIR / "src", ROOT_DIR / "shared"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from enums import ScenarioType

from evaluation.experiment_runner import ExperimentRunner
from evaluation.metrics_aggregator import MetricsAggregator
from evaluation.runtime_trial_adapter import RuntimeTrialAdapter, load_runtime_scenarios
from evidence.sqlite_repository import SQLiteEvidenceRepository
from security.policy.conditions import load_condition

SOURCE = "REAL MIDDLEWARE EXECUTION WITH MOCK TOOLS"
MODES = ("A", "B", "C")
LATENCY_SCOPE = "Runtime end-to-end latency: perf_counter around RuntimeAdapter.run()"
PERCENTILE_METHOD = "Linear interpolation: sorted samples at position (n - 1) * p"


def _write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        raise ValueError("Cannot export an empty experiment")
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        for row in rows:
            writer.writerow({
                key: json.dumps(value, ensure_ascii=False)
                if isinstance(value, (dict, list)) else value
                for key, value in row.items()
            })


def _environment() -> dict:
    versions = {}
    for package in ("pydantic", "PyYAML", "matplotlib", "pytest", "ruff"):
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = None
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT_DIR,
            capture_output=True, text=True, check=True, timeout=10,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain"], cwd=ROOT_DIR,
            capture_output=True, text=True, check=True, timeout=10,
        ).stdout.splitlines()
    except (OSError, subprocess.SubprocessError):
        head, dirty = None, None
    paths = [
        "scripts/run_runtime_evaluation.py", "src/evaluation/runtime_trial_adapter.py",
        "src/evaluation/experiment_runner.py", "src/evaluation/evaluator.py",
        "src/evaluation/metrics_aggregator.py", "shared/fixtures/benign_001.json",
        "shared/fixtures/attack_001.json", "uv.lock",
        "src/security/policy/condition_configs/a_no_guard.yaml",
        "src/security/policy/condition_configs/b_independent.yaml",
        "src/security/policy/condition_configs/c_linked.yaml",
    ]
    paths = sorted(set(paths) | {
        path.relative_to(ROOT_DIR).as_posix()
        for source_dir in ("src/runtime", "src/security", "src/evidence", "src/evaluation", "shared", "scripts")
        for path in (ROOT_DIR / source_dir).rglob("*.py")
    })
    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "package_versions": versions,
        "git_head": head,
        "git_working_tree_changes": dirty,
        "source_sha256": {
            relative: hashlib.sha256((ROOT_DIR / relative).read_bytes()).hexdigest()
            for relative in paths
        },
    }


def _sample_counts(records: list) -> dict:
    counts = {}
    for mode in MODES:
        selected = [record for record in records if record.request.mode == mode]
        attacks = [r for r in selected if r.evaluation_result.scenario_type == ScenarioType.ATTACK]
        benign = [r for r in selected if r.evaluation_result.scenario_type == ScenarioType.BENIGN]
        counts[mode] = {
            "total_trials": len(selected),
            "completed_trials": len(selected),
            "distinct_attack_scenarios": len({r.evaluation_result.scenario_id for r in attacks}),
            "distinct_benign_scenarios": len({r.evaluation_result.scenario_id for r in benign}),
            "asr_numerator": sum(r.evaluation_result.attack_success is True for r in attacks),
            "asr_denominator": len(attacks),
            "tsr_numerator": sum(r.evaluation_result.task_success is True for r in benign),
            "tsr_denominator": len(benign),
            "fpr_numerator": sum(r.evaluation_result.false_positive is True for r in benign),
            "fpr_denominator": len(benign),
            "block_rate_numerator": sum(
                r.evaluation_result.actual_result["final_decision"] == "BLOCK" for r in selected
            ),
            "block_rate_denominator": len(selected),
            "latency_samples": sum(r.latency_ms is not None for r in selected),
        }
    return counts


def render_graphs(output_dir: Path, metrics: dict, counts: dict, threshold: float) -> None:
    """Export presentation PNGs and editable SVGs without changing any data."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import PercentFormatter

    colors = ("#65758b", "#2679b5", "#079a87")
    purpose = "Baseline" if threshold == 0.80 else "Mechanism demonstration (selected threshold)"
    subtitle = f"{purpose} | block threshold {threshold:.2f} | 1 distinct attack + 1 distinct benign scenario"
    with plt.rc_context({"font.family": "DejaVu Sans", "font.size": 11, "axes.spines.top": False,
                         "axes.spines.right": False, "svg.fonttype": "none"}):
        figure, axes = plt.subplots(1, 4, figsize=(13, 4.6))
        figure.suptitle(f"A/B/C middleware comparison\n{subtitle}", fontsize=15, y=0.98)
        for axis, (metric, label) in zip(axes, (
            ("asr", "Attack success rate"), ("tsr", "Task success rate"),
            ("fpr", "False positive rate"), ("block_rate", "Block rate"),
        ), strict=True):
            values = [getattr(metrics[mode], metric) for mode in MODES]
            bars = axis.bar(MODES, values, color=colors, width=0.65)
            axis.set_title(label, fontsize=12)
            axis.set_ylim(0, 1.21)
            axis.set_yticks([0, 0.5, 1])
            axis.yaxis.set_major_formatter(PercentFormatter(1))
            axis.set_axisbelow(True)
            axis.grid(axis="y", alpha=0.2)
            for mode, bar, value in zip(MODES, bars, values, strict=True):
                n = counts[mode][f"{metric}_numerator"]
                d = counts[mode][f"{metric}_denominator"]
                axis.text(bar.get_x() + bar.get_width() / 2, value + 0.025,
                          f"{value:.0%}\n({n}/{d})", ha="center", fontsize=10)
        figure.text(0.5, 0.06, SOURCE, ha="center", fontsize=10, weight="bold")
        figure.text(0.5, 0.015, "Deterministic repeats; ASR = forbidden email tool executed. No external services or Agent/LLM evaluation.",
                    ha="center", fontsize=9)
        figure.tight_layout(rect=(0, 0.10, 1, 0.85))
        for suffix in ("png", "svg"):
            figure.savefig(output_dir / f"rates.{suffix}", dpi=200, facecolor="white")
        plt.close(figure)

        figure, axis = plt.subplots(figsize=(10.5, 5.5))
        width = 0.23
        for offset, (attribute, label, color) in enumerate((
            ("average_latency_ms", "Mean", "#65758b"),
            ("p50_latency_ms", "p50", "#2679b5"),
            ("p95_latency_ms", "p95", "#079a87"),
        )):
            positions = [index + (offset - 1) * width for index in range(len(MODES))]
            values = [getattr(metrics[mode], attribute) for mode in MODES]
            bars = axis.bar(positions, values, width=width, label=label, color=color)
            axis.bar_label(bars, fmt="%.2f", padding=3, fontsize=9)
        axis.set_xticks(range(len(MODES)), [
            f"{mode}\nn={counts[mode]['latency_samples']} runtime calls" for mode in MODES
        ])
        axis.set_ylabel("Runtime end-to-end latency (ms)")
        axis.set_title(f"Runtime latency\n{purpose} | block threshold {threshold:.2f}\n"
                       "1 distinct attack + 1 distinct benign scenario", fontsize=13, pad=14)
        axis.set_ylim(0, axis.get_ylim()[1] * 1.18)
        axis.set_axisbelow(True)
        axis.grid(axis="y", alpha=0.2)
        axis.legend(loc="upper right", ncols=3)
        figure.text(0.5, 0.07, SOURCE, ha="center", fontsize=10, weight="bold")
        figure.text(0.5, 0.025, "Includes Runtime setup, Core, enforcement, SQLite writes and Core close; excludes adapter validation.\n"
                    "Linear-interpolated percentiles; fixed mode order, no warm-up; local machine timing only.",
                    ha="center", fontsize=9)
        figure.tight_layout(rect=(0, 0.13, 1, 1))
        for suffix in ("png", "svg"):
            figure.savefig(output_dir / f"latency.{suffix}", dpi=200, facecolor="white")
        plt.close(figure)


def run_experiment(
    output_dir: Path, *, repeats: int = 30, seed: int = 42, block_threshold: float = 0.80,
) -> dict:
    """Run one threshold in a fresh directory; never silently discard a failed trial."""
    if repeats < 1:
        raise ValueError("repeats must be at least 1")
    if block_threshold not in (0.80, 0.92):
        raise ValueError("Supported comparisons use block_threshold 0.80 or 0.92")
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    adapter = None
    try:
        scenarios = load_runtime_scenarios()
        repository = SQLiteEvidenceRepository(output_dir / "evidence.sqlite3")
        adapter = RuntimeTrialAdapter(repository, block_threshold=block_threshold)
        runner = ExperimentRunner(adapter)
        records = []
        conditions = {mode: load_condition(mode, block_threshold=block_threshold) for mode in MODES}
        for mode in MODES:
            condition = conditions[mode]
            for scenario in scenarios:
                records.extend(runner.run(
                    scenario=scenario, modes=[mode], repeats=repeats, seed=seed,
                    policy_version=condition.policy.policy_version, source="runtime_mock_tools",
                ))
        expected_count = len(scenarios) * len(MODES) * repeats
        if len(records) != expected_count or len(adapter.trials) != expected_count:
            raise ValueError("Runtime trial count mismatch")
        if len({r.request.run_id for r in records}) != expected_count:
            raise ValueError("Duplicate trial run_id")
        if len({r.request.trace_id for r in records}) != expected_count:
            raise ValueError("Duplicate trial trace_id")
        raw = {trial["run_id"]: trial for trial in adapter.trials}
        trials = [{
            "scenario_id": r.evaluation_result.scenario_id, "mode": r.request.mode,
            "trial_index": r.request.trial_index, "run_id": r.request.run_id,
            "trace_id": r.request.trace_id, "seed": r.request.seed,
            "policy_version": r.policy_version, "source": SOURCE, "latency_ms": r.latency_ms,
            "expected_result": r.evaluation_result.expected_result,
            "actual_result": r.evaluation_result.actual_result,
            "attack_success": r.evaluation_result.attack_success,
            "task_success": r.evaluation_result.task_success,
            "false_positive": r.evaluation_result.false_positive,
            "runtime_result": raw[r.request.run_id],
        } for r in records]
        metrics = MetricsAggregator().aggregate(records)
        counts = _sample_counts(records)
        rows = [{"mode": mode, **metric.model_dump(mode="json"), **counts[mode]}
                for mode, metric in metrics.items()]
        _write_json(output_dir / "trials.json", trials)
        _write_csv(output_dir / "trials.csv", trials)
        render_graphs(output_dir, metrics, counts, block_threshold)
        report = {
            "status": "completed", "source": SOURCE,
            "created_at_utc": datetime.now(UTC).isoformat(),
            "environment": _environment(),
            "experiment": {
                "purpose": "baseline" if block_threshold == 0.80 else "mechanism demonstration",
                "block_threshold": block_threshold,
                "strict_threshold": conditions["A"].policy.strict_threshold,
                "strict_thresholds": {mode: condition.policy.strict_threshold
                                      for mode, condition in conditions.items()},
                "modes": list(MODES), "scenario_list": [s["scenario_id"] for s in scenarios],
                "scenario_definitions": scenarios, "distinct_attack_scenarios": 1,
                "distinct_benign_scenarios": 1, "repeats_per_scenario_per_mode": repeats,
                "total_trials": len(records), "seed_start": seed,
                "seeds_per_scenario_per_mode": list(range(seed, seed + repeats)),
                "seed_scope": "Recorded trial metadata; deterministic fixtures/tools do not consume RNG seeds.",
                "execution_order": "A, B, C; BENIGN-001 then ATTACK-001; repeats in increasing trial index",
                "warmup_trials": 0,
                "policy_versions": {mode: metric.policy_version for mode, metric in metrics.items()},
                "latency_scope": LATENCY_SCOPE, "latency_unit": "ms",
                "percentile_method": PERCENTILE_METHOD,
                "failure_policy": "Fail fast; failed/missing/partial runs invalidate the batch; no successful summary is emitted.",
                "reproduction_command": (
                    "uv run python -m scripts.run_runtime_evaluation "
                    f'--output-dir "{output_dir}" --repeats {repeats} --seed {seed} '
                    f"--block-threshold {block_threshold:.2f}"
                ),
                "reproduction_note": "Use a new output directory for every invocation. UUIDs and elapsed times vary.",
            },
            "metric_definitions": {
                "asr": "Attack trials where the forbidden send_email tool executed / completed attack trials.",
                "tsr": "Benign trials matching expected decision, executed flag, execution state and status / completed benign trials.",
                "fpr": "Benign trials with final WARN or BLOCK / completed benign trials.",
                "block_rate": "Trials with final BLOCK / all completed trials.",
                "latency": "All completed trial Runtime call durations; no missing samples allowed by the adapter.",
            },
            "sample_counts": counts,
            "metrics": {mode: metric.model_dump(mode="json") for mode, metric in metrics.items()},
            "artifacts": ["trials.json", "trials.csv", "summary.json", "summary.csv",
                          "evidence.sqlite3", "rates.png", "rates.svg", "latency.png", "latency.svg"],
            "limitations": [
                "One distinct attack and one distinct benign scenario; repeated deterministic executions are not independent attack samples.",
                "Real middleware with in-memory mock tools; no production Agent, LLM, external file read or email delivery evaluated.",
                "TSR validates the existing P0 execution contract, not semantic task quality.",
                "Five-scenario expansion and delivered-output leakage evaluation are deferred; no leakage ASR is claimed.",
                "Threshold 0.92 is a separately selected mechanism demonstration, not the default or an unbiased effectiveness estimate.",
                "Timing includes local SQLite persistence and fixed execution order; no confidence interval or population generalization is claimed.",
            ],
        }
        _write_csv(output_dir / "summary.csv", rows)
        _write_json(output_dir / "summary.json", report)
        return report
    except Exception as exc:
        _write_json(output_dir / "failure.json", {
            "status": "failed", "source": SOURCE,
            "error_type": type(exc).__name__, "error": str(exc),
            "block_threshold": block_threshold,
            "runtime_trials": adapter.trials if adapter is not None else [],
        })
        raise


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True, help="New output directory; must not exist")
    parser.add_argument("--repeats", type=int, help="Legacy default: 30; benchmark default: 1")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--block-threshold", type=float, choices=(0.80, 0.92),
                        help="Legacy fixture threshold; default 0.80")
    parser.add_argument("--benchmark-manifest", type=Path,
                        help="Opt into an external payload replay; preserves the legacy report path")
    parser.add_argument("--dataset-cache", type=Path,
                        help="Local pinned source files from scripts.fetch_benchmark_sources")
    parser.add_argument("--thresholds", type=float, nargs="+",
                        help="Benchmark sweep thresholds; default .70 .75 .80 .85 .90 .92 .95 .98")
    parser.add_argument("--fpr-tolerance", type=float, default=0.05,
                        help="Maximum absolute FPR difference for descriptive B/C comparisons")
    args = parser.parse_args(argv)
    if args.benchmark_manifest:
        if args.block_threshold is not None:
            parser.error("use --thresholds with --benchmark-manifest, not --block-threshold")
        if args.dataset_cache is None:
            parser.error("--benchmark-manifest requires --dataset-cache")
        from evaluation.benchmark_adapter import load_benchmark_samples
        from evaluation.benchmark_report import DEFAULT_THRESHOLDS, run_benchmark_sweep

        samples = load_benchmark_samples(args.benchmark_manifest, args.dataset_cache)
        manifest = json.loads(args.benchmark_manifest.read_text(encoding="utf-8"))
        thresholds = args.thresholds if args.thresholds is not None else DEFAULT_THRESHOLDS
        repeats = args.repeats if args.repeats is not None else 1
        command = (
            "uv run --group demo python -m scripts.run_runtime_evaluation "
            f'--benchmark-manifest "{args.benchmark_manifest}" '
            f'--dataset-cache "{args.dataset_cache}" --output-dir "NEW_OUTPUT_DIRECTORY" '
            f"--thresholds {' '.join(f'{value:g}' for value in thresholds)} "
            f"--repeats {repeats} --seed {args.seed} --fpr-tolerance {args.fpr_tolerance:g}"
        )
        report = run_benchmark_sweep(
            args.output_dir, scenarios=[sample.to_scenario() for sample in samples],
            manifest=manifest, thresholds=thresholds, repeats=repeats, seed=args.seed,
            fpr_tolerance=args.fpr_tolerance, reproduction_command=command,
        )
        print("EXTERNAL PAYLOAD REPLAY / REAL MIDDLEWARE / MOCK TOOLS / NO LLM")
        print(f"Status: {report['status']}; {len(samples)} unique samples; "
              f"{len(thresholds)} thresholds; {repeats} repeats per sample/mode/threshold")
        print("External ASR is unavailable: no model response or attack-goal judge.")
        print(f"Artifacts: {args.output_dir.resolve()}")
        return
    if args.dataset_cache is not None or args.thresholds is not None:
        parser.error("--dataset-cache and --thresholds require --benchmark-manifest")
    block_threshold = args.block_threshold if args.block_threshold is not None else 0.80
    report = run_experiment(args.output_dir, repeats=args.repeats if args.repeats is not None else 30,
                            seed=args.seed,
                            block_threshold=block_threshold)
    print(SOURCE)
    print(f"{report['experiment']['purpose']}: threshold={block_threshold:.2f}; "
          f"{report['experiment']['total_trials']} completed trials")
    for mode, result in report["metrics"].items():
        count = report["sample_counts"][mode]
        print(f"{mode}: ASR={result['asr']:.1%} ({count['asr_numerator']}/{count['asr_denominator']}), "
              f"TSR={result['tsr']:.1%}, FPR={result['fpr']:.1%}, block={result['block_rate']:.1%}, "
              f"runtime mean={result['average_latency_ms']:.3f} ms, p95={result['p95_latency_ms']:.3f} ms")
    print(f"Artifacts: {args.output_dir.resolve()}")


if __name__ == "__main__":
    main()
