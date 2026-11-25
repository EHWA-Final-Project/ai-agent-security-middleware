"""Headless matplotlib figures from separated external evaluation aggregates."""

from collections import defaultdict

from .external_mcp_adapter import record_sha256
from .external_mcp_comparison import compare_cd
from .external_mcp_report import FIXTURE_LABEL


def render_graphs(bundle, evidence_lookup):
    import matplotlib
    matplotlib.use("Agg")
    matplotlib.rcParams["svg.hashsalt"] = "guardon-external-mcp-report-v1"
    import matplotlib.pyplot as plt
    from matplotlib.ticker import PercentFormatter

    scope = bundle["metadata"]["execution_scope"]
    if scope == "mapping_only" or (scope == "actual_llm_mcp" and not any(
        t.evidence_validated is True and t.observation.run_status == "completed" for t in bundle["trials"]
    )):
        return []
    output = bundle["directory"] / "graphs"
    output.mkdir()
    cohorts = defaultdict(list)
    for group in bundle["metrics"]["groups"]:
        key = {k: v for k, v in group["group"].items() if k not in {"condition", "policy_version"}}
        if not key["policy_comparison_key"]:
            key["unreviewed_policy_version"] = group["group"]["policy_version"]
        cohorts[record_sha256(key)].append(group)
    generated = []
    for digest, groups in sorted(cohorts.items()):
        # Never average two policy versions under the same condition label.
        conditions = [g["group"]["condition"] for g in groups]
        if len(conditions) != len(set(conditions)):
            raise ValueError("graph cohort contains incompatible policy versions")
        indexed = {g["group"]["condition"]: g for g in groups}
        first = groups[0]["group"]
        title = FIXTURE_LABEL if scope == "fixture_execution" else "ACTUAL AGENT/MCP OBSERVATIONS"
        model_label = "none (fixture)" if scope == "fixture_execution" else first["model_configuration_sha256"][:10]
        subtitle = f"{first['dataset']} / {first['attack_family']} | model={model_label}"
        settings = f"PI-T01={first['output_injection_scan']} | cohort={digest[:12]} | candidate-only"
        policy_note = " | ".join(f"{c}: {g['group']['policy_version']}" for c, g in sorted(indexed.items()))

        def save(fig, stem, title=title, subtitle=subtitle, settings=settings, policy_note=policy_note, digest=digest):
            fig.suptitle(title + "\n" + subtitle, fontsize=11)
            fig.text(.5, .025, settings + "\n" + policy_note, ha="center", fontsize=7, wrap=True)
            fig.tight_layout(rect=(0, .12, 1, .88))
            for ext in ("png", "svg"):
                path = output / f"{stem}_{digest[:12]}.{ext}"
                fig.savefig(path, dpi=140, metadata={"Date": None} if ext == "svg" else None)
                generated.append(path)
            plt.close(fig)

        def panel(ax, name, caption, indexed=indexed):
            for i, condition in enumerate("ABCD"):
                metric = indexed[condition]["rates"][name] if condition in indexed else None
                if metric and metric["rate"] is not None:
                    value = metric["rate"]
                    ax.bar(i, value, color="#346b9b", width=.6)
                    ax.text(i, value + .035, f"{metric['numerator']}/{metric['denominator']}", ha="center", fontsize=9)
                else:
                    ax.text(i, .5, "Unavailable\nn=0" if metric else "Not run", ha="center", fontsize=9, color="#666666")
            ax.set(title=caption, ylim=(0, 1.18), xlim=(-.6, 3.6))
            ax.set_xticks(range(4), list("ABCD"))
            ax.yaxis.set_major_formatter(PercentFormatter(1))
            ax.grid(axis="y", alpha=.2)

        fig, axes = plt.subplots(2, 2, figsize=(11, 8))
        for ax, name, caption in zip(axes.flat, (
            "asr_end_to_end", "asr_exposure_conditioned", "tsr_benign", "tsr_attacked",
        ), ("End-to-end ASR", "Exposure-conditioned ASR", "Benign task success", "Attacked task success"), strict=True):
            panel(ax, name, caption)
        save(fig, "semantic_rates")
        fig, axes = plt.subplots(1, 3, figsize=(13, 5.5))
        for ax, name, caption in zip(axes, (
            "guard_warn_or_block_fpr", "benign_guard_block", "benign_guard_warn",
        ), ("Guard WARN-or-BLOCK FPR", "Benign Guard BLOCK", "Benign Guard WARN (overlaps BLOCK)"), strict=True):
            panel(ax, name, caption)
        save(fig, "guard_rates")
        fig, axes = plt.subplots(1, 2, figsize=(11, 5.5))
        for ax, name, caption in zip(axes, ("pre_tool_block", "post_tool_output_block"),
                                     ("Pre-tool BLOCK / eligible candidates", "Post-tool Output BLOCK / eligible executions"), strict=True):
            panel(ax, name, caption)
        save(fig, "boundary_rates")
        scopes = sorted({s for g in groups for s in g["latency_by_scope"]})
        for latency_scope in scopes or [None]:
            fig, ax = plt.subplots(figsize=(11, 5.5))
            for i, condition in enumerate("ABCD"):
                latency = indexed.get(condition, {}).get("latency_by_scope", {}).get(latency_scope)
                if latency and latency["mean_ms"] is not None:
                    ax.bar(i, latency["mean_ms"], color="#346b9b")
                    ax.annotate(f"n={latency['count']}", (i, latency["mean_ms"]), ha="center", xytext=(0, 5), textcoords="offset points")
                else:
                    ax.text(i, .5, "Unavailable\nn=0", ha="center", transform=ax.get_xaxis_transform())
            ax.set_xticks(range(4), list("ABCD"))
            ax.set(xlim=(-.6, 3.6), ylabel="Mean milliseconds", title=latency_scope or "Latency not measured")
            save(fig, "latency_" + record_sha256({"scope": latency_scope})[:8])
        selected = [t for t in bundle["trials"] if any(
            t.condition == g["group"]["condition"] and t.policy_version == g["group"]["policy_version"]
            and t.provenance["dataset_id"] == g["group"]["dataset"]
            and t.provenance["attack_id"] == g["group"]["attack_family"]
            and record_sha256(t.model or {}) == g["group"]["model_configuration_sha256"]
            and t.policy_comparison_key == g["group"]["policy_comparison_key"]
            and t.manifest_sha256 == g["group"]["manifest_sha256"]
            and t.experiment_id == g["group"]["experiment_id"]
            and t.output_injection_scan == g["group"]["output_injection_scan"]
            and t.code_revision == g["group"]["code_revision"]
            and t.backend_id == g["group"]["backend_id"]
            and t.timeout_seconds == g["group"]["timeout_seconds"]
            for g in groups
        )]
        cd = compare_cd(selected, evidence_lookup)
        fig, ax = plt.subplots(figsize=(11, 6))
        ax.axis("off")
        text = [f"C/D matched pairs: n={cd['matched_pairs']}",
                f"Unmatched trials: {cd['unmatched_trials']}; incomplete/incompatible pairs: {cd['incomplete_or_incompatible_pairs']}"]
        if cd["matched_pairs"]:
            text.extend(f"{k}: {v}" for k, v in sorted(cd["decision_transitions"].items()))
            text.extend([
                f"Comparable-boundary BLOCK relaxations: {cd['comparable_boundary_block_relaxations']}",
                f"Regression candidates requiring review: {cd['regression_candidates_requiring_review']}",
                f"Verified attack-outcome regressions: {cd['verified_attack_outcome_regressions']}",
            ])
        else:
            text.append("Decision transitions and safety comparisons unavailable")
        ax.text(.05, .95, "\n".join(text), va="top", fontsize=12, linespacing=1.6)
        save(fig, "cd_transitions")
    return generated
