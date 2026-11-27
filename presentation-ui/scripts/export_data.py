"""Deterministic public export using the existing read-only validation loader."""

import argparse
import csv
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PUBLIC = ROOT / "presentation-ui/public"
sys.path[:0] = [str(ROOT / "demo"), str(ROOT / "src"), str(ROOT / "shared")]

from actual_results import load_results

from security.policy.conditions import load_condition

GRAPHS = [
    ("execution", "실행 상태", "dashboard/graphs/execution_status.png"),
    ("boundaries", "실행·전달 경계", "dashboard/graphs/operational_boundaries.png"),
    ("unauthorized", "비인가 Tool 관측", "dashboard/graphs/unauthorized_tool_observations.png"),
    ("responses", "생성 응답 사후 분석", "dashboard/graphs/generated_response_findings.png"),
    ("latency", "Backend Latency (s)", "latency/backend_latency.png"),
]


def source_bytes(path):
    """Use repository bytes, independent of Windows checkout line endings."""
    relative = path.relative_to(ROOT).as_posix()
    original = subprocess.run(["git", "show", f"HEAD:{relative}"], cwd=ROOT, check=True, capture_output=True).stdout
    local = path.read_bytes()
    if local.replace(b"\r\n", b"\n") != original.replace(b"\r\n", b"\n"):
        raise ValueError(f"Source differs from committed archive: {relative}")
    return original


def export(check=False):
    data = load_results()
    source = ROOT / "reports/external_mcp_actual"
    runtime_path = ROOT / "reports/runtime_demo/public_observations.json"
    manifest_path = ROOT / "benchmarks/mcp_external_manifest.json"
    runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload = {
        "schema": "guardon-presentation-v1", "mode": "recorded",
        "config": data["configuration"], "trials": data["trial_observations"],
        "candidates": data["candidate_observations"], "guards": data["individual_guard_results"],
        "selections": data["model_tool_selections"], "comparisons": data["matched_abcd_comparisons"],
        "operationalMetrics": data["operational_metrics"], "semanticMetrics": data["semantic_metrics"],
        "metricDefinitions": data["metric_definitions"],
        "formalMetrics": data["report_summary_ko"]["공식지표"],
        "runtime": runtime, "sources": manifest["samples"],
        "policies": [{"condition": name, **load_condition(name).policy.model_dump(mode="json")} for name in "ABCD"],
    }
    with (source / "latency/backend_latency_summary.csv").open(encoding="utf-8", newline="") as stream:
        payload["latency"] = list(csv.DictReader(stream))
    artifacts = {}
    graphs = []
    for graph_id, title, relative in GRAPHS:
        raw = (source / relative).read_bytes()
        if raw[:8] != b"\x89PNG\r\n\x1a\n":
            raise ValueError("Unexpected graph format")
        width, height = struct.unpack(">II", raw[16:24])
        filename = relative.rsplit("/", 1)[-1]
        artifacts[f"graphs/{filename}"] = raw
        graphs.append({"id": graph_id, "title": title, "src": f"graphs/{filename}", "width": width, "height": height})
    payload["graphs"] = graphs
    inputs = [runtime_path, manifest_path, source / "experiment_configuration.json", source / "latency/backend_latency_summary.csv"]
    inputs += [source / "dashboard" / f"{name}.json" for name in (
        "trial_observations", "candidate_observations", "individual_guard_results", "model_tool_selections",
        "matched_abcd_comparisons", "operational_metrics", "semantic_metrics", "metric_definitions", "report_summary_ko",
    )]
    payload["sourceHashes"] = {p.relative_to(ROOT).as_posix(): hashlib.sha256(source_bytes(p)).hexdigest() for p in inputs}
    artifacts["data/trial_observations.csv"] = source_bytes(source / "dashboard/trial_observations.csv")
    artifacts["data/guardon.json"] = (json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    for relative, raw in artifacts.items():
        path = PUBLIC / relative
        if check:
            if not path.is_file() or path.read_bytes() != raw:
                raise ValueError(f"Public artifact differs from validated source: {relative}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
    print(f"{'Verified' if check else 'Exported'} 48 benchmark attempts and {len(runtime['records'])} separate Runtime records; {len(graphs)} original graphs")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    export(parser.parse_args().check)
