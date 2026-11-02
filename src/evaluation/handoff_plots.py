"""Figures from audited aggregate rows; no Runtime or model execution."""

from collections import defaultdict


def caption(split):
    if split not in {"tune", "holdout"}:
        raise ValueError("explicit tune or holdout split required")
    return "tuning split, provisional" if split == "tune" else "holdout split, provisional"


def fraction(cell, metric):
    n, d = cell[metric + "_numerator"], cell[metric + "_denominator"]
    return f"{n}/{d} ({n/d:.1%})" if d else "Unavailable (n=0)"


def benign_rows(cells):
    """Collapse thresholds only when every displayed numerator/denominator agrees."""
    groups = defaultdict(list)
    for cell in cells:
        if cell["condition"] not in {"B", "C"}:
            continue
        for kind in ("read", "send"):
            values = tuple(fraction(cell, metric) for metric in (
                f"fpr_{kind}_warn_block", f"fpr_{kind}_block", f"completion_{kind}"))
            groups[(cell["condition"], kind, values)].append(float(cell["threshold"]))
    return [[mode, "read_file" if kind == "read" else "send_email",
             ", ".join(f"{t:.2f}" for t in sorted(thresholds)), *values]
            for (mode, kind, values), thresholds in sorted(groups.items())]


def render_figures(output, cells, latency, metadata, *, split, sources, toolpolicy):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import PercentFormatter

    tag = caption(split)
    thresholds = sorted({float(c["threshold"]) for c in cells if c["condition"] in {"B", "C"}})
    indexed = {(c["condition"], float(c["threshold"])): c for c in cells if c["condition"] in {"B", "C"}}
    if set(indexed) != {(m, t) for m in ("B", "C") for t in thresholds}:
        raise ValueError("missing paired B/C threshold cells")
    policy = "no ToolPolicy" if toolpolicy == "absent" else "ToolPolicy enforcement enabled; not Guard detection accuracy"
    source_text = ", ".join(sources)
    source_note = "Tensor Trust licensing unresolved" if any("tensor-trust" in s for s in sources) else "Source permissions require review"

    def save(fig, name, footer, bottom=.23):
        fig.text(.5, .025, tag + "\n" + footer, ha="center", fontsize=9)
        fig.tight_layout(rect=(0, bottom, 1, .97))
        for suffix in ("png", "svg"):
            fig.savefig(output / f"{name}.{suffix}", dpi=180)
        plt.close(fig)

    def panel(ax, metric, title):
        for mode, marker, color in (("B", "o", "#2469a0"), ("C", "s", "#ce6400")):
            selected = [indexed[(mode, t)] for t in thresholds]
            ax.plot(range(len(thresholds)), [c[metric] for c in selected], marker=marker, color=color, label=mode)
            for i, c in enumerate(selected):
                value = c[metric]
                if value is not None:
                    ax.annotate(f"{c[metric+'_numerator']}/{c[metric+'_denominator']}", (i, value),
                                xytext=(0, 10 if mode == "B" else -17), textcoords="offset points",
                                ha="center", fontsize=8, color=color)
        ax.set_xticks(range(len(thresholds)), [f"{t:.2f}" for t in thresholds])
        ax.set(title=title, xlabel="Block threshold (categorical spacing)", ylabel="Executed trial fraction", ylim=(-.09, 1.12))
        ax.yaxis.set_major_formatter(PercentFormatter(1)); ax.grid(alpha=.2); ax.legend()

    definition = "Experiment supplies the tool intent; this is tool execution, NOT real-model ASR."
    fig, ax = plt.subplots(figsize=(12, 6.5))
    panel(ax, "attack_tool_execution", "Attacker-supplied Tool execution — B/C")
    save(fig, "attack_tool_execution", f"Each point labels executed / attack trials; {policy}\nSources: {source_text}; {source_note}\n{definition}")
    fig, axes = plt.subplots(1, 2, figsize=(16, 6.5))
    panel(axes[0], "attack_tool_execution_direct", "Direct attacks — supplied Tool execution")
    panel(axes[1], "attack_tool_execution_indirect", "Indirect attacks — supplied Tool execution")
    save(fig, "direct_indirect", f"Each point labels executed / subgroup trials; {policy}\nSources: {source_text}; {source_note}\n{definition}")

    rows = benign_rows(cells)
    # Long threshold lists get their own line, preserving every threshold.
    for row in rows:
        parts = row[2].split(", ")
        row[2] = ", ".join(parts[:4]) + ("\n" + ", ".join(parts[4:]) if len(parts)>4 else "")
    fig, ax = plt.subplots(figsize=(15, max(5.5, 2.5 + .55 * len(rows))))
    ax.axis("off")
    ax.set_title("Benign outcomes: warnings, blocking and actual Runtime completion", pad=20)
    table = ax.table(cellText=rows, colLabels=["Mode", "Tool", "Thresholds", "WARN-inclusive FPR\n(WARN or BLOCK)",
                     "BLOCK-only FPR", "Actual completion\n(executed AND delivered)"], loc="center",
                     cellLoc="center", colWidths=[.05,.10,.23,.20,.17,.25])
    table.auto_set_font_size(False); table.set_fontsize(10); table.scale(1, 3)
    for (row, _), cell in table.get_celld().items():
        cell.set_facecolor("#dae7f3" if row == 0 else ("#f1f5f9" if row % 2 else "white"))
    save(fig, "benign_warn_block", f"Each entry is numerator / eligible benign trials; {policy}\nWARN can permit Tool execution while withholding output: BLOCK-only FPR is not completion.\nCompletion is mechanical, not semantic task success. Identical threshold rows are grouped.", bottom=.24)

    if latency:
        fig, ax = plt.subplots(figsize=(12, 6.5))
        for offset, (field, label) in enumerate((("mean_ms", "Mean (ms)"), ("p50_ms", "p50 (ms)"), ("p95_ms", "p95 (ms)"))):
            bars = ax.bar([i+(offset-1)*.25 for i in range(len(latency))], [float(r[field]) for r in latency], width=.25, label=label)
            ax.bar_label(bars, fmt="%.3f", padding=3, fontsize=9)
        ax.set_xticks(range(len(latency)), [f"{r['condition']}\nn={r['n']}" for r in latency])
        ax.set(ylabel="Security Core time (ms)", title="Separate synthetic Security Core microbenchmark")
        ax.legend()
        environment = f"Environment: {metadata.get('platform','not supplied')}; Python {metadata.get('python','not supplied')}; CPUs {metadata.get('cpu_count','not supplied')}"
        save(fig, "core_latency", "Separate synthetic Security Core microbenchmark; not split-specific dataset timing.\n" + environment +
             f"\nRepeats/scenario: {metadata.get('repeat','not supplied')}; warm-up: {metadata.get('warmup','not supplied')} (excluded); seed: {metadata.get('seed','not supplied')}\n" +
             "Excludes model calls, real tools, SQLite and Runtime end-to-end. Local timing; no speed superiority claim.", bottom=.28)
