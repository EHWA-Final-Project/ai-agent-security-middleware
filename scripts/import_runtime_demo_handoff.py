"""Export only public observation fields; never extract raw ZIP contents."""

import argparse
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile

TOP = [
    "schema_version",
    "scenario_id",
    "condition",
    "trial_run_id",
    "trial_trace_id",
    "requested_model",
    "policy_version",
    "output_injection_scan",
    "initial_inspection_mode",
    "run_status",
    "loop_completed",
    "timed_out",
    "error_stage",
    "error_type",
    "candidate_trace_complete",
    "guard_trace_complete",
    "final_response_observed",
    "final_response_delivered_to_user",
]
TOOL = [
    "candidate_id",
    "parent_candidate_id",
    "model_turn",
    "tool_name",
    "runtime_tool_call_id",
    "run_id",
    "trace_id",
    "runtime_scenario_id",
    "runtime_status",
    "security_decision",
    "execution_state",
    "sdk_call_count",
    "server_call_counts",
    "tool_executed",
    "output_allowed",
    "output_queued",
    "blocked_notice_queued",
    "blocked_notice_delivered",
    "output_delivered",
    "output_destination",
    "followup_model_turn",
    "runtime_error_codes",
    "evidence_refs",
    "evidence_event_types",
    "evidence_identity_verified",
]
TURN = [
    "turn",
    "model",
    "elapsed_seconds",
    "finish_reason",
    "tool_selection_observed",
    "tool_call_count",
    "response_text_chars",
    "selection_error",
]
SDK = ["method", "timestamp", "candidate_id", "tool_name", "invoked", "mcp_call_id"]


def project(row, keys):
    return {key: row.get(key) for key in keys}


def import_handoff(source):
    records = []
    with ZipFile(source) as archive:
        manifests = [
            n
            for n in archive.namelist()
            if n.count("/") == 1 and n.endswith("/manifest.json")
        ]
        if len(manifests) != 1:
            raise ValueError("Expected one Runtime Agent manifest")
        prefix = manifests[0].rsplit("/", 1)[0] + "/"
        manifest = json.loads(archive.read(manifests[0]))
        for entry in manifest:
            name = prefix + entry["summary"]
            if ".." in Path(name).parts or not name.startswith(prefix):
                raise ValueError("Unsafe archive entry")
            payload = archive.read(name)
            raw = json.loads(payload)
            if any(
                raw[k] != entry[k]
                for k in ("condition", "scenario_id", "policy_version", "run_status")
            ):
                raise ValueError("Manifest/summary mismatch")
            row = project(raw, TOP)
            for key, fields in [
                ("tool_executions", TOOL),
                ("model_turns", TURN),
                ("sdk_calls", SDK),
            ]:
                row[key] = (
                    [project(item, fields) for item in raw.get(key, [])]
                    if key in raw
                    else None
                )
            row.update(
                category=entry["category"],
                source_entry=entry["summary"],
                source_sha256=hashlib.sha256(payload).hexdigest(),
            )
            records.append(row)
        fixed_manifest = json.loads(
            archive.read(prefix + "tool_policy_fixture/manifest.json")
        )
    return {
        "kind": "historical_runtime_validation_not_benchmark",
        "source_zip_sha256": hashlib.sha256(Path(source).read_bytes()).hexdigest(),
        "handoff_code_reference": "2bbc873763e404cf9bb68f85e9403852206c7de4",
        "all_trials_rerun_at_reference": False,
        "agent_record_count": len(records),
        "fixed_candidate_record_count": len(fixed_manifest),
        "raw_content_exported": False,
        "records": records,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result = import_handoff(args.archive)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"Exported {result['agent_record_count']} historical Agent summaries; no raw payloads"
    )
