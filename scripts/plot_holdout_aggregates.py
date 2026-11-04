"""Check supplied Holdout aggregates and render deterministic PNG/SVG figures.

This never reruns an experiment. An optional --raw-verification report binds the
verified footer to matching inputs; without it, only aggregates are checked. Use a new
output directory: python -m scripts.plot_holdout_aggregates --source for-wana.zip
--output new_graphs. An extracted directory is also accepted.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import platform
import zipfile
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter

REQUIRED = (
    "holdout_results.json",
    "run_record_holdout.json",
    "sweep_holdout_summary.csv",
    "sweep_policy_holdout_summary.csv",
    "c_cause_holdout.csv",
)
OPTIONAL_RAW = (
    "sweep_holdout_trials.csv",
    "sweep_policy_holdout_trials.csv",
    "guards_holdout.csv",
)
THRESHOLDS = (0.70, 0.75, 0.80, 0.85, 0.90, 0.92, 0.95, 0.98)
RATES = (
    "ASR",
    "ASR_indirect",
    "ASR_direct",
    "pre_tool_block",
    "FPR_read(WARN|BLOCK)",
    "FPR_read(BLOCK)",
    "TSR_read",
    "FPR_send(WARN|BLOCK)",
    "FPR_send(BLOCK)",
)
COUNTS = ("n_attack", "n_benign_read", "n_benign_send")
SUMMARY_FIELDS = {"condition", "threshold", *COUNTS, *RATES}
CAUSE_PARTS = ("cumulative_risk", "strict_warn_escalation", "guard_block_or_other")
CAUSE_COUNTS = ("n_attack", "n_pre_tool_block", *CAUSE_PARTS, "single_guard_ge_thr")
CAUSE_FIELDS = {"threshold", "cause_source", *CAUSE_COUNTS}
LABEL = "Aggregate-checked; not independently verified against raw trials"
TOL = 1e-10


def load_files(source: Path) -> dict[str, bytes]:
    """Read known members without extracting or modifying the source archive."""
    if source.is_file() and zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as archive:
            files = {}
            for name in REQUIRED + OPTIONAL_RAW:
                matches = [
                    item
                    for item in archive.infolist()
                    if not item.is_dir() and Path(item.filename).name == name
                ]
                if len(matches) > 1:
                    raise ValueError(f"Ambiguous duplicate ZIP entries for {name}")
                if matches:
                    files[name] = archive.read(matches[0])
            return files
    if source.is_dir():
        root = source
        if (
            not (root / REQUIRED[0]).exists()
            and (root / "for-wana" / REQUIRED[0]).exists()
        ):
            root = root / "for-wana"
        return {
            name: (root / name).read_bytes()
            for name in REQUIRED + OPTIONAL_RAW
            if (root / name).is_file()
        }
    raise ValueError(f"Expected a ZIP or an existing directory: {source}")


def parse_csv(blob: bytes) -> list[dict[str, str]]:
    reader = csv.DictReader(io.StringIO(blob.decode("utf-8-sig"), newline=None))
    fields = reader.fieldnames
    if not fields or len(set(fields)) != len(fields) or any(not f for f in fields):
        raise ValueError("Missing or duplicate CSV headers")
    rows = list(reader)
    if any(None in row or any(value is None for value in row.values()) for row in rows):
        raise ValueError("CSV row width does not match its header")
    return rows


def parse_json(blob: bytes) -> dict:
    def unique_fields(pairs):
        result = {}
        for field, value in pairs:
            if field in result:
                raise ValueError(f"Duplicate JSON field: {field}")
            result[field] = value
        return result

    def reject_constant(value):
        raise ValueError(f"Nonfinite JSON number: {value}")

    return json.loads(
        blob.decode("utf-8-sig"),
        object_pairs_hook=unique_fields,
        parse_constant=reject_constant,
    )


def number(value: Any) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Expected a finite number, got {value!r}") from exc
    if isinstance(value, bool) or not math.isfinite(result):
        raise ValueError(f"Expected a finite number, got {value!r}")
    return result


def count(value: Any, *, positive: bool = False) -> int:
    result = number(value)
    if not result.is_integer() or result < (1 if positive else 0):
        raise ValueError(
            f"Expected {'positive' if positive else 'nonnegative'} integer count"
        )
    return int(result)


def close(left: Any, right: Any) -> bool:
    return math.isclose(number(left), number(right), rel_tol=0, abs_tol=TOL)


def key(row: dict[str, Any]) -> tuple[str, float | None]:
    value = row.get("threshold")
    return str(row["condition"]), None if value in (None, "") else number(value)


def compare_rows(rows: list[dict[str, str]], json_rows: list[dict[str, Any]]) -> None:
    """Check schema, complete A/B/C grid, CSV/JSON agreement and rate arithmetic."""
    if (
        not isinstance(json_rows, list)
        or len(rows) != len(json_rows)
        or len(rows) != 17
    ):
        raise ValueError(
            "Expected 17 A/B/C sweep rows and exact CSV/JSON row agreement"
        )
    if any(
        not isinstance(row, dict) or set(row) != SUMMARY_FIELDS
        for row in rows + json_rows
    ):
        raise ValueError("Missing or unexpected summary fields")
    by_key = {key(row): row for row in json_rows}
    if len(by_key) != len(json_rows):
        raise ValueError("Duplicate condition/threshold rows in JSON")
    seen = set()
    denominators = set()
    for row in rows:
        row_key = key(row)
        if row_key in seen or row_key not in by_key:
            raise ValueError(f"Missing or duplicate condition/threshold {row_key}")
        seen.add(row_key)
        expected = by_key[row_key]
        for field in COUNTS + RATES:
            if not close(row[field], expected[field]):
                raise ValueError(f"CSV/JSON value mismatch in {row_key}: {field}")
        denominators.add(tuple(count(row[field], positive=True) for field in COUNTS))
        for field in RATES:
            if not 0 <= number(row[field]) <= 1:
                raise ValueError(f"Rate outside [0,1] in {row_key}: {field}")
        if not close(number(row["ASR"]) + number(row["pre_tool_block"]), 1):
            raise ValueError(
                f"Attack tool execution + pre-tool block != 1 in {row_key}"
            )
        subtypes = [number(row[field]) for field in ("ASR_direct", "ASR_indirect")]
        if not min(subtypes) - TOL <= number(row["ASR"]) <= max(subtypes) + TOL:
            raise ValueError(f"Overall ASR outside subtype range in {row_key}")
        for kind in ("read", "send"):
            if (
                number(row[f"FPR_{kind}(BLOCK)"])
                > number(row[f"FPR_{kind}(WARN|BLOCK)"]) + TOL
            ):
                raise ValueError(f"BLOCK rate exceeds WARN|BLOCK rate in {row_key}")
        for field in RATES:
            # Subtype denominators are absent from these tables; never invent them.
            if field in {"ASR_direct", "ASR_indirect"}:
                continue
            denominator = (
                "n_benign_read"
                if "read" in field
                else ("n_benign_send" if "send" in field else "n_attack")
            )
            implied_count = number(row[field]) * number(row[denominator])
            if not math.isclose(
                implied_count, round(implied_count), rel_tol=0, abs_tol=1e-7
            ):
                raise ValueError(
                    f"Rate does not imply an integer count in {row_key}: {field}"
                )
    expected_grid = {("A", None)} | {(c, t) for c in ("B", "C") for t in THRESHOLDS}
    if seen != expected_grid:
        raise ValueError("Missing A/B/C conditions or B/C thresholds")
    if len(denominators) != 1:
        raise ValueError("Inconsistent denominators across summary rows")


def compare_causes(causes, json_causes, summary) -> None:
    if not isinstance(json_causes, list) or len(causes) != 8 or len(json_causes) != 8:
        raise ValueError("Expected eight block cause rows in CSV and JSON")
    if any(
        not isinstance(row, dict) or set(row) != CAUSE_FIELDS
        for row in causes + json_causes
    ):
        raise ValueError("Missing or unexpected block cause fields")
    by_threshold = {number(row["threshold"]): row for row in json_causes}
    if len(by_threshold) != 8:
        raise ValueError("Duplicate block cause thresholds in JSON")
    sweep = {key(row): row for row in summary}
    seen = set()
    for row in causes:
        threshold = number(row["threshold"])
        if (
            threshold in seen
            or threshold not in THRESHOLDS
            or threshold not in by_threshold
        ):
            raise ValueError("Missing or duplicate block cause thresholds")
        seen.add(threshold)
        values = {field: count(row[field]) for field in CAUSE_COUNTS}
        if sum(values[field] for field in CAUSE_PARTS) != values["n_pre_tool_block"]:
            raise ValueError("Block cause counts disagree with total pre-tool blocks")
        if (
            not values["single_guard_ge_thr"]
            <= values["n_pre_tool_block"]
            <= values["n_attack"]
        ):
            raise ValueError("Block cause counts disagree with bounds")
        for condition, field in (
            ("B", "single_guard_ge_thr"),
            ("C", "n_pre_tool_block"),
        ):
            cell = sweep[(condition, threshold)]
            if values["n_attack"] != count(cell["n_attack"]) or not math.isclose(
                values[field],
                number(cell["pre_tool_block"]) * values["n_attack"],
                rel_tol=0,
                abs_tol=1e-7,
            ):
                raise ValueError(
                    f"Block cause counts disagree with default {condition} sweep"
                )
        expected = by_threshold[threshold]
        if (
            row["cause_source"] != "block_cause"
            or row["cause_source"] != expected["cause_source"]
        ):
            raise ValueError("Unsupported or inconsistent block cause source")
        if any(values[field] != count(expected[field]) for field in CAUSE_COUNTS):
            raise ValueError("Block cause CSV/JSON values disagree")


def _metadata(results: dict, record: dict) -> None:
    if results.get("kind") != "benchmark_evaluation" or any(
        obj.get("split") != "holdout" for obj in (results, record)
    ):
        raise ValueError("Expected benchmark_evaluation on the holdout split")
    for group, required, other in (
        ("run", {"core_commit"}, record),
        ("data", {"samples_sha256", "n_samples_in_split"}, record.get("data", {})),
    ):
        values = results.get(group)
        if (
            not isinstance(values, dict)
            or not isinstance(other, dict)
            or not required <= values.keys()
        ):
            raise ValueError(f"Missing required {group} metadata")
        if any(
            field not in other or value != other[field]
            for field, value in values.items()
        ):
            raise ValueError(
                f"Conflicting {group} metadata between results and run record"
            )
    if not results["run"]["core_commit"] or not results["data"]["samples_sha256"]:
        raise ValueError("Missing provenance identifiers")
    count(results["data"]["n_samples_in_split"], positive=True)
    policy = record.get("policy", {})
    if not isinstance(policy, dict):
        raise ValueError("Expected policy metadata object")  # noqa: TRY004 - invalid file data
    for result_field, record_field in (
        ("tool_policy", "tool_policy_policy_run"),
        ("headline_block_threshold", "headline_block_threshold"),
    ):
        if result_field in results and results[result_field] != policy.get(
            record_field
        ):
            raise ValueError(f"Conflicting policy metadata: {result_field}")
    if "threshold_sweep" in policy and policy["threshold_sweep"] != list(THRESHOLDS):
        raise ValueError("Policy metadata thresholds disagree with sweep")
    if "conditions" in policy and policy["conditions"] != ["A", "B", "C"]:
        raise ValueError("Policy metadata conditions disagree with sweep")
    if policy.get("headline_block_threshold", 0.8) not in THRESHOLDS:
        raise ValueError("Headline threshold is absent from sweep")


def verify(files: dict[str, bytes]) -> tuple[dict, list, list, list, dict]:
    missing = sorted(set(REQUIRED) - files.keys())
    if missing:
        raise ValueError(f"Missing required aggregate files: {', '.join(missing)}")
    results = parse_json(files["holdout_results.json"])
    record = parse_json(files["run_record_holdout.json"])
    if not isinstance(results, dict) or not isinstance(record, dict):
        raise ValueError("Expected JSON objects for results and run record")  # noqa: TRY004 - invalid file data
    _metadata(results, record)
    hashes = {
        name: hashlib.sha256(blob).hexdigest() for name, blob in sorted(files.items())
    }
    recorded_hashes = record.get("output_sha256")
    if not isinstance(recorded_hashes, dict):
        raise ValueError("Missing output_sha256 in run record")  # noqa: TRY004 - invalid file data
    checked_hashes = {}
    for name in REQUIRED[2:] + OPTIONAL_RAW:
        if name in files:
            if hashes[name] != recorded_hashes.get(name):
                raise ValueError(f"SHA256 mismatch or missing recorded hash: {name}")
            checked_hashes[name] = hashes[name]
    summary = parse_csv(files["sweep_holdout_summary.csv"])
    policy = parse_csv(files["sweep_policy_holdout_summary.csv"])
    causes = parse_csv(files["c_cause_holdout.csv"])
    compare_rows(summary, results.get("sweep_default"))
    compare_rows(policy, results.get("sweep_with_tool_policy"))
    if any(count(summary[0][field]) != count(policy[0][field]) for field in COUNTS):
        raise ValueError(
            "Inconsistent denominators between default and ToolPolicy sweeps"
        )
    baseline = next(row for row in summary if row["condition"] == "A")
    policy_baseline = next(row for row in policy if row["condition"] == "A")
    for field in RATES:
        expected = (
            1 if field in {"ASR", "ASR_direct", "ASR_indirect", "TSR_read"} else 0
        )
        if not close(baseline[field], expected) or not close(
            policy_baseline[field], expected
        ):
            raise ValueError("Condition A disagrees with no-Guard baseline semantics")
    compare_causes(causes, results.get("c_block_cause"), summary)
    audit = {
        "status": "aggregate_checked_only",
        "label": LABEL,
        "split": "holdout",
        "raw_trial_recalculation_performed": False,
        "independently_verified_against_raw_trials": False,
        "missing_raw_files": [name for name in OPTIONAL_RAW if name not in files],
        "present_raw_files": [name for name in OPTIONAL_RAW if name in files],
        "input_sha256": hashes,
        "run_record_hashes_matched": checked_hashes,
        "recorded_outputs_not_supplied": sorted(set(recorded_hashes) - files.keys()),
        "row_counts": {
            "default": len(summary),
            "tool_policy": len(policy),
            "c_causes": len(causes),
        },
        "thresholds": list(THRESHOLDS),
        "reported_run": results["run"],
        "reported_data": results["data"],
        "reported_policy": record.get("policy", {}),
        "trial_denominators_per_condition_threshold": {
            field: count(baseline[field]) for field in COUNTS
        },
        "checks_passed": [
            "Supplied CSV bytes match hashes in supplied run record",
            "Shared results/run-record metadata agree",
            "Complete and unique A/B/C grids; CSV and JSON aggregate values agree",
            "Finite rates in [0,1]; positive consistent integer denominators",
            "ASR + pre_tool_block = 1; overall ASR within subtype range",
            "BLOCK <= WARN|BLOCK; rates with supplied denominators imply integer counts",
            "No-Guard A baseline agrees across sweeps",
            "C cause CSV/JSON agree; components sum to C blocks; single-Guard count agrees with B",
        ],
        "limitations": [
            LABEL
            + ". Raw files, even if present, are only hash-checked, not recalculated.",
            "Hashes establish consistency with the supplied record, not independent provenance or authenticity.",
            "ASR is execution of an experiment-supplied forbidden tool call, not real-model attack success.",
            "ToolPolicy results reflect allowlist configuration, not Guard detection performance.",
            "Single supplied run; no confidence intervals or independent experiment rerun.",
            "Subtype denominators are absent from aggregate tables; weighted subtype ASR is not recalculated.",
            "Sample counts and trial-type denominators have different units; their mapping is not verified.",
            "Source data, split membership, frozen rules, and run-record provenance are not independently verified.",
        ],
    }
    return results, summary, policy, causes, audit


RAW_LABEL = "Holdout | Raw-trial aggregation verified"
MODE_COLORS = {"A": "#64748b", "B": "#0072b2", "C": "#d55e00"}


def validate_raw_report(report, files, summary, policy, causes):
    """Bind a successful arithmetic report to these exact inputs, never Runtime evidence."""
    from scripts.verify_holdout_raw import canonical, compare_summary

    required_totals = {
        "summary_csv",
        "summary_json",
        "causes_csv",
        "causes_json",
        "guard_metadata",
    }
    if (
        report.get("schema_version") != "holdout-raw-verification-v1"
        or report.get("status") != "raw_arithmetic_verified"
        or report.get("runtime_execution_verified") is not False
        or not required_totals <= report.get("mismatch_totals", {}).keys()
        or any(value != 0 for value in report["mismatch_totals"].values())
        or any(report.get("mismatches", {}).values())
    ):
        raise ValueError("Expected a successful raw arithmetic verification report")
    recorded = parse_json(files["run_record_holdout.json"])["output_sha256"]
    for name in REQUIRED + OPTIONAL_RAW:
        expected = (
            hashlib.sha256(files[name]).hexdigest() if name in files else recorded[name]
        )
        if report.get("input_sha256", {}).get(name) != expected:
            raise ValueError(f"Raw verification input SHA256 mismatch: {name}")
    for name, rows in (("default", summary), ("tool_policy", policy)):
        cells = report["sweeps"][name]["cells"]
        if compare_summary(canonical(cells), canonical(rows)):
            raise ValueError("Raw report cells disagree with plotted summary")
        for cell in cells:
            for kind in ("direct", "indirect"):
                denominator = count(
                    cell[f"attack_tool_execution_{kind}_denominator"], positive=True
                )
                numerator = count(cell[f"attack_tool_execution_{kind}_numerator"])
                if not close(
                    numerator / denominator, cell[f"attack_tool_execution_{kind}"]
                ):
                    raise ValueError("Raw report subtype counts disagree with rates")
            if (
                sum(
                    cell[f"attack_tool_execution_{k}_denominator"]
                    for k in ("direct", "indirect")
                )
                != cell["n_attack"]
            ):
                raise ValueError("Raw report subtype denominators disagree with total")
    compare_causes(causes, report["c_causes"], summary)


def _render(
    output: Path,
    summary: list,
    policy: list,
    causes: list,
    *,
    raw_report=None,
    label=LABEL,
) -> None:
    from matplotlib.lines import Line2D

    summary = sorted(summary, key=key)
    policy = sorted(policy, key=key)
    colors = MODE_COLORS
    headline = 0.80

    def cells(rows, condition):
        return sorted((r for r in rows if r["condition"] == condition), key=key)

    def at(rows, mode, field):
        return number(next(r[field] for r in rows if key(r) == (mode, headline)))

    def line(ax, rows, mode, field, *, block=False):
        selected = cells(rows, mode)
        # A broad blue line/ring remains visible beneath the narrower orange line.
        ax.plot(
            [number(r["threshold"]) for r in selected],
            [number(r[field]) for r in selected],
            color=colors[mode],
            linewidth=3.2 if mode == "B" else 1.8,
            linestyle="--" if block or mode == "C" else "-",
            marker=("s" if mode == "B" else "x")
            if block
            else ("o" if mode == "B" else "D"),
            markersize=9 if mode == "B" else 5,
            markerfacecolor="white" if mode == "B" or block else colors[mode],
            markeredgewidth=1.6,
            zorder=3 if mode == "B" else 4,
        )

    def setup(ax, title, *, zoom=False, highlight=True):
        ax.set_title(title, loc="left", fontsize=14, fontweight="bold", pad=14)
        ax.set_xlabel("Block threshold", labelpad=7)
        ax.set_xticks(THRESHOLDS, [f"{t:.2f}" for t in THRESHOLDS], rotation=45)
        ax.set_xlim(0.688, 0.992)
        ax.yaxis.set_major_formatter(PercentFormatter(1, decimals=2 if zoom else 0))
        if not zoom:
            ax.set_ylim(-0.04, 1.06)
            ax.set_yticks([0, 0.25, 0.5, 0.75, 1])
        ax.grid(axis="y", color="#e2e8f0", linewidth=0.8, zorder=0)
        if highlight:
            ax.axvline(
                headline, color="#94a3b8", linestyle=":", linewidth=1.2, zorder=1
            )
            for tick in ax.get_xticklabels():
                if tick.get_text() == "0.80":
                    tick.set_fontweight("bold")
                    tick.set_color("#0f172a")

    def legend(fig, *, benign=False, baseline=True):
        handles = []
        if baseline:
            handles.append(
                Line2D(
                    [],
                    [],
                    color=colors["A"],
                    linestyle=":",
                    linewidth=2,
                    label="Mode A · no Guard",
                )
            )
        for mode, meaning in (("B", "independent"), ("C", "linked")):
            handles.append(
                Line2D(
                    [],
                    [],
                    color=colors[mode],
                    linewidth=2.5,
                    marker="o" if mode == "B" else "D",
                    markerfacecolor="white" if mode == "B" else colors[mode],
                    linestyle="-" if mode == "B" else "--",
                    label=f"Mode {mode} · {meaning}",
                )
            )
        if benign:
            handles.extend(
                [
                    Line2D(
                        [],
                        [],
                        color="#475569",
                        marker="o",
                        label="Circle/diamond: WARN or BLOCK",
                    ),
                    Line2D(
                        [],
                        [],
                        color="#475569",
                        marker="s",
                        linestyle="--",
                        markerfacecolor="white",
                        label="Square/cross: BLOCK only",
                    ),
                ]
            )
        fig.legend(
            handles=handles,
            loc="upper center",
            bbox_to_anchor=(0.52, 0.90),
            ncol=len(handles),
            frameon=False,
            fontsize=12,
            handlelength=2.5,
            columnspacing=1.5,
        )

    def save(fig, name, title, subtitle, note):
        fig.suptitle(title, x=0.065, y=0.975, ha="left", fontsize=24, fontweight="bold")
        fig.text(0.065, 0.922, subtitle, fontsize=13, color="#475569")
        fig.text(
            0.065,
            0.105 if "\n" in note else 0.08,
            note,
            fontsize=12,
            color="#475569",
            va="top",
            linespacing=1.2,
        )
        fig.text(0.065, 0.025, label, fontsize=12, color="#0f172a", fontweight="bold")
        try:
            fig.savefig(
                output / f"{name}.png",
                dpi=220,
                metadata={"Software": "Holdout evaluation plotter"},
            )
            fig.savefig(
                output / f"{name}.svg",
                metadata={"Date": None, "Creator": "Holdout evaluation plotter"},
            )
        finally:
            plt.close(fig)

    def fraction(value, denominator):
        return f"{round(value * denominator):,}/{denominator:,}"

    with matplotlib.rc_context(
        {
            "font.family": "DejaVu Sans",
            "font.size": 13,
            "axes.labelsize": 13,
            "xtick.labelsize": 11,
            "ytick.labelsize": 12,
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.edgecolor": "#cbd5e1",
            "text.color": "#0f172a",
            "svg.hashsalt": "holdout-evaluation-v2",
            "svg.fonttype": "none",
        }
    ):
        fig, axes = plt.subplots(1, 3, figsize=(16, 9))
        fig.subplots_adjust(left=0.065, right=0.975, bottom=0.26, top=0.75, wspace=0.25)
        n_attack = count(summary[0]["n_attack"])
        denominators = {"ASR": n_attack}
        if raw_report:
            first = raw_report["sweeps"]["default"]["cells"][0]
            denominators.update(
                {
                    f"ASR_{k}": count(first[f"attack_tool_execution_{k}_denominator"])
                    for k in ("direct", "indirect")
                }
            )
        for ax, field, title in zip(
            axes,
            ("ASR", "ASR_direct", "ASR_indirect"),
            ("All attacks", "Direct attacks", "Indirect attacks"),
        ):
            denominator = denominators.get(field)
            for mode in ("B", "C"):
                line(ax, summary, mode, field)
            ax.axhline(
                number(summary[0][field]), color=colors["A"], linestyle=":", linewidth=2
            )
            setup(
                ax,
                f"{title} · n={denominator:,}"
                if denominator
                else f"{title} · n unavailable",
            )
            values = []
            for mode in ("A", "B", "C"):
                value = (
                    number(summary[0][field])
                    if mode == "A"
                    else at(summary, mode, field)
                )
                text = f"{mode}  {value:.1%}"
                if denominator:
                    text += f"  ({fraction(value, denominator)})"
                values.append(text)
            ax.text(
                0,
                -0.33,
                "At 0.80   " + values[0] + "\n" + "   |   ".join(values[1:]),
                transform=ax.transAxes,
                fontsize=11,
                linespacing=1.7,
            )
        axes[0].set_ylabel("Forbidden Tool Execution Rate (%)")
        legend(fig)
        save(
            fig,
            "holdout_attack_tool_execution",
            "Forbidden Tool Execution Rate (%)",
            "Default settings · All eight thresholds retained · Dotted guide marks the representative threshold 0.80",
            "Execution of experiment-supplied forbidden Mock Tool calls; not real-model ASR.",
        )

        fig, axes = plt.subplots(1, 2, figsize=(16, 9))
        fig.subplots_adjust(left=0.075, right=0.97, bottom=0.23, top=0.75, wspace=0.22)
        for ax, field, title in zip(
            axes,
            ("ASR", "pre_tool_block"),
            ("Forbidden Tool Execution Rate (%)", "Pre-tool BLOCK Rate (%)"),
        ):
            for mode in ("B", "C"):
                line(ax, policy, mode, field)
            ax.axhline(
                number(policy[0][field]), color=colors["A"], linestyle=":", linewidth=2
            )
            setup(ax, title)
            b, c = at(policy, "B", field), at(policy, "C", field)
            ax.text(
                0.5,
                0.48,
                f"B: {b:.0%}  ·  C: {c:.0%}\nAt 0.80: {fraction(b, n_attack)} / {fraction(c, n_attack)}",
                transform=ax.transAxes,
                ha="center",
                fontsize=18,
                fontweight="bold",
                linespacing=1.8,
            )
        legend(fig)
        save(
            fig,
            "holdout_tool_policy",
            "ToolPolicy configuration effects",
            f"Configured allowlist · n={n_attack:,} attack trials per condition · Distinct markers expose coincident B/C curves",
            "Explicit allowlist configuration, not improved Guard detection accuracy.\nExecution of experiment-supplied forbidden Mock Tool calls; not real-model ASR.",
        )

        fig, axes = plt.subplots(2, 3, figsize=(16, 9))
        fig.subplots_adjust(
            left=0.09, right=0.975, bottom=0.20, top=0.75, wspace=0.30, hspace=0.80
        )
        legend(fig, benign=True, baseline=False)
        for row_index, (row_axes, rows) in enumerate(zip(axes, (summary, policy))):
            y = 0.64 if row_index == 0 else 0.32
            fig.text(
                0.018,
                y,
                "DEFAULT" if row_index == 0 else "TOOLPOLICY",
                rotation=90,
                va="center",
                fontsize=12,
                fontweight="bold",
                color="#475569" if row_index == 0 else "#00695c",
            )
            for ax, kind in zip(row_axes[:2], ("read", "send")):
                fields = [f"FPR_{kind}({s})" for s in ("WARN|BLOCK", "BLOCK")]
                peak = max(number(r[f]) for r in rows for f in fields)
                zoom = peak < 0.05
                n = count(rows[0][f"n_benign_{kind}"])
                for mode in ("B", "C"):
                    for field in fields:
                        line(ax, rows, mode, field, block=field.endswith("(BLOCK)"))
                setup(
                    ax,
                    f"Normal {kind} · n={n}" + (" · ZOOM" if zoom else ""),
                    zoom=zoom,
                    highlight=False,
                )
                if zoom:
                    ax.set_ylim(-max(peak, 0.001) * 0.12, max(peak, 0.001) * 1.8)
                    ax.set_yticks([0, peak, peak * 1.5])
                wb = "; ".join(
                    f"{m} {fraction(at(rows, m, fields[0]), n)}" for m in ("B", "C")
                )
                block = "; ".join(
                    f"{m} {fraction(at(rows, m, fields[1]), n)}" for m in ("B", "C")
                )
                ax.text(
                    0.025,
                    0.18,
                    f"0.80 · WARN or BLOCK: {wb}\nBLOCK only: {block}",
                    transform=ax.transAxes,
                    fontsize=10,
                    linespacing=1.7,
                    bbox={"facecolor": "white", "edgecolor": "none", "alpha": 0.90},
                )
            ax = row_axes[2]
            n = count(rows[0]["n_benign_read"])
            for mode in ("B", "C"):
                line(ax, rows, mode, "TSR_read")
            floor = min(number(r["TSR_read"]) for r in rows)
            zoom = floor > 0.95
            setup(
                ax,
                f"Read completion · n={n}" + (" · ZOOM" if zoom else ""),
                zoom=zoom,
                highlight=False,
            )
            if zoom:
                gap = max(1 - floor, 0.001)
                ax.set_ylim(1 - gap * 1.8, 1 + gap * 0.1)
                ax.set_yticks([1 - gap * 1.5, floor, 1])
            ax.text(
                0.03,
                0.15,
                "At 0.80: "
                + "  |  ".join(
                    f"{m} {fraction(at(rows, m, 'TSR_read'), n)}" for m in ("B", "C")
                ),
                transform=ax.transAxes,
                fontsize=11,
            )
        save(
            fig,
            "holdout_benign_outcomes",
            "Benign outcomes across thresholds",
            "Top: default settings    /    Bottom: configured ToolPolicy    ·    ZOOM panels explicitly use narrow percentage ranges",
            "WARN or BLOCK includes BLOCK. Read completion requires execution AND delivered output.\nMock Tool execution does not mean an actual email was sent. Coincident curves retain both mode markers.",
        )

        fig, ax = plt.subplots(figsize=(16, 9))
        fig.subplots_adjust(left=0.075, right=0.97, bottom=0.23, top=0.74)
        ordered = sorted(causes, key=lambda row: number(row["threshold"]))
        x = list(range(len(ordered)))
        bottom = [0] * len(ordered)
        for field, color, title in zip(
            CAUSE_PARTS,
            (colors["C"], "#e5ad35", "#8b80b6"),
            ("Cumulative risk", "STRICT WARN escalation", "Other blocking causes"),
        ):
            values = [count(row[field]) for row in ordered]
            ax.bar(
                x, values, bottom=bottom, label=title, color=color, width=0.65, zorder=2
            )
            for position, value, base in zip(x, values, bottom):
                if value:
                    ax.text(
                        position,
                        base + value / 2,
                        str(value),
                        ha="center",
                        va="center",
                        fontsize=13,
                        fontweight="bold",
                        color="#0f172a" if field != "cumulative_risk" else "white",
                    )
            bottom = [a + b for a, b in zip(bottom, values)]
        single = [count(r["single_guard_ge_thr"]) for r in ordered]
        ax.plot(
            x,
            single,
            "o--",
            color=colors["B"],
            linewidth=2,
            markersize=7,
            zorder=3,
            label="Single Guard ≥ threshold · overlapping subset",
        )
        for position, total, subset in zip(x, bottom, single):
            ax.annotate(
                str(total),
                (position, total),
                xytext=(0, 9),
                textcoords="offset points",
                ha="center",
                fontsize=13,
                fontweight="bold",
            )
            ax.annotate(
                str(subset),
                (position, subset),
                xytext=(18, 9) if subset else (0, -19),
                textcoords="offset points",
                ha="center",
                fontsize=11,
                color=colors["B"],
                bbox={"facecolor": "white", "edgecolor": "none", "pad": 1},
            )
        index = next(
            i for i, r in enumerate(ordered) if number(r["threshold"]) == headline
        )
        ax.axvspan(index - 0.44, index + 0.44, color="#e2e8f0", zorder=0)
        ax.set_xticks(x, [f"{number(r['threshold']):.2f}" for r in ordered])
        ax.get_xticklabels()[index].set_fontweight("bold")
        ax.set_xlabel("Block threshold · highlighted: 0.80", labelpad=12)
        ax.set_ylabel("Pre-tool BLOCK decisions (count)")
        ax.set_ylim(-max(bottom) * 0.08, max(bottom) * 1.18)
        ax.grid(axis="y", color="#e2e8f0", zorder=0)
        handles, labels = ax.get_legend_handles_labels()
        fig.legend(
            handles,
            labels,
            loc="upper center",
            bbox_to_anchor=(0.52, 0.885),
            ncol=2,
            frameon=False,
            fontsize=13,
        )
        save(
            fig,
            "holdout_c_block_causes",
            "Mode C · why forbidden Tool calls were blocked",
            f"Default settings · n={n_attack:,} attack trials per threshold · Totals above bars; cause counts inside segments",
            "Stacked categories sum to total pre-tool BLOCK decisions.\nThe blue single-Guard line is an overlapping subset, NOT an additional blocking cause.",
        )


def json_bytes(document):
    """One deterministic file serialization; hashes always cover these exact bytes."""
    return (
        json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")


def write_validation_metadata(output, audit, raw_report_path=None):
    """Finalize the downstream report after the raw report is immutable on disk.

    Dependency direction: figures -> raw report -> aggregate metadata.
    The raw report never hashes this metadata or itself.
    """
    if raw_report_path is not None:
        import os

        blob = raw_report_path.read_bytes()
        report = parse_json(blob)
        if (
            report.get("status") != "raw_arithmetic_verified"
            or report.get("runtime_execution_verified") is not False
            or any(report["mismatch_totals"].values())
        ):
            raise ValueError("Cannot finalize metadata with a failed raw report")
        audit["aggregate_stage"] = {
            "status": "aggregate_checked_only",
            "raw_files_in_source": audit["present_raw_files"],
            "raw_files_absent_from_source": audit["missing_raw_files"],
        }
        audit.update(
            {
                "schema_version": "holdout-figure-validation-v2",
                "status": "raw_arithmetic_verified",
                "verification_scope": "raw_trial_arithmetic",
                "verification_method": "validated_raw_report",
                "runtime_execution_verified": False,
                "raw_trial_recalculation_performed": True,
                "independently_verified_against_raw_trials": True,
                "label": RAW_LABEL,
                "missing_raw_files": [],
                "present_raw_files": list(OPTIONAL_RAW),
                "input_sha256": report["input_sha256"],
                "run_record_hashes_matched": report["run_record_hashes_matched"],
                "limitations": report["limitations"],
                "raw_verification_report": Path(
                    os.path.relpath(raw_report_path, output)
                ).as_posix(),
                "raw_verification_report_sha256": hashlib.sha256(blob).hexdigest(),
                "raw_verification_hash_scope": "exact_file_bytes",
            }
        )
        audit["recorded_outputs_not_supplied"] = sorted(
            set(audit["recorded_outputs_not_supplied"]) - set(OPTIONAL_RAW)
        )
    else:
        audit.update(
            {
                "schema_version": "holdout-figure-validation-v2",
                "verification_scope": "aggregate_only",
                "runtime_execution_verified": False,
            }
        )
    (output / "aggregate_validation.json").write_bytes(json_bytes(audit))
    return audit


def generate(
    source: Path,
    output: Path,
    *,
    raw_verification: dict | None = None,
    _defer_metadata: bool = False,
) -> dict:
    if output.exists():
        raise FileExistsError(
            "Use a NEW output directory; existing outputs are preserved"
        )
    files = load_files(source)
    _, summary, policy, causes, audit = verify(files)
    if raw_verification is not None:
        validate_raw_report(raw_verification, files, summary, policy, causes)
        audit["figure_label"] = RAW_LABEL
        audit["figure_verification_status"] = "raw_arithmetic_verified"
    else:
        audit["figure_label"] = LABEL
        audit["figure_verification_status"] = "aggregate_checked_only"
    audit["source_archive_sha256"] = (
        hashlib.sha256(source.read_bytes()).hexdigest() if source.is_file() else None
    )
    audit["generator"] = {
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "python": platform.python_version(),
        "matplotlib": matplotlib.__version__,
        "reproducibility": "Byte reproducible for identical inputs, script and rendering environment; no timestamps or output paths embedded.",
    }
    output.mkdir(parents=True, exist_ok=False)
    _render(
        output,
        summary,
        policy,
        causes,
        raw_report=raw_verification,
        label=audit["figure_label"],
    )
    audit["figure_sha256"] = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(output.iterdir())
        if path.suffix in {".png", ".svg"}
    }
    if not _defer_metadata:
        report_path = None
        if raw_verification is not None:
            report_path = output / "raw_verification.json"
            report_path.write_bytes(json_bytes(raw_verification))
        write_validation_metadata(output, audit, report_path)
    return audit


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", required=True, type=Path, help="Supplied ZIP or extracted directory"
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="New output directory (must not exist)",
    )
    parser.add_argument(
        "--raw-verification",
        type=Path,
        help="Successful raw_verification.json bound to these inputs",
    )
    args = parser.parse_args()
    try:
        report = (
            parse_json(args.raw_verification.read_bytes())
            if args.raw_verification
            else None
        )
        audit = generate(args.source, args.output, raw_verification=report)
    except (ValueError, OSError, KeyError, zipfile.BadZipFile) as exc:
        parser.exit(2, f"error: {exc}\n")
    print(
        f"{audit['figure_label']}\nWrote PNG/SVG figures and aggregate_validation.json to {args.output.resolve()}"
    )


if __name__ == "__main__":
    main()
