"""Public export excludes raw payloads even when a ZIP contains them."""

import json
import sys
from pathlib import Path
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from import_runtime_demo_handoff import import_handoff


def test_export_drops_raw_fields_and_preserves_unknown(tmp_path):
    source = tmp_path / "handoff.zip"
    raw = {"condition": "C", "scenario_id": "normal", "policy_version": "v1", "run_status": "completed",
           "final_response_delivered_to_user": None, "raw_response": "PRIVATE_RESPONSE",
           "tool_executions": [{"candidate_id": "c1", "arguments": "PRIVATE_ARGUMENTS", "output": "PRIVATE_OUTPUT"}]}
    manifest = [{"summary": "normal/observation_summary.json", "category": "normal",
                 **{key: raw[key] for key in ("condition", "scenario_id", "policy_version", "run_status")}}]
    with ZipFile(source, "w") as archive:
        archive.writestr("handoff/manifest.json", json.dumps(manifest))
        archive.writestr("handoff/normal/observation_summary.json", json.dumps(raw))
        archive.writestr("handoff/tool_policy_fixture/manifest.json", "[]")
    exported = import_handoff(source)
    assert "PRIVATE_" not in json.dumps(exported)
    assert exported["records"][0]["final_response_delivered_to_user"] is None
    assert exported["records"][0]["sdk_calls"] is None
    assert exported["records"][0]["source_sha256"]
