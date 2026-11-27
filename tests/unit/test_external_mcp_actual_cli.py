"""Offline CLI contracts. Runtime/model execution is explicitly stubbed."""

import csv
import json
from types import SimpleNamespace

import pytest

from evaluation import external_mcp_cli as cli
from evaluation.external_mcp_evidence import EvidenceView
from evaluation.mcp_trial_observation import TrialSidecar
from evidence.sqlite_repository import SQLiteEvidenceRepository
from tests.unit import test_external_mcp_phase3 as phase3
from tests.unit import test_external_mcp_runtime_backend as runtime_tests

inventory = phase3.inventory
backend_setup = runtime_tests.setup
install_runtime = runtime_tests.install_runtime


def args(tmp_path, sample, *extra):
    return cli.parser().parse_args([
        "actual", "--backend", "actual-agent", "--dataset-root", str(tmp_path / "dataset"),
        "--output-dir", str(tmp_path / "output"), "--sample-id", sample,
        "--conditions", "C", "--seed", "none", "--repeats", "1", "--timeout", "600", *extra,
    ])


@pytest.fixture
def routed(tmp_path, monkeypatch, backend_setup):
    case, manifest, _, _, _ = backend_setup
    calls = install_runtime(monkeypatch, backend_setup)
    monkeypatch.setattr(cli, "load_verified_cases", lambda *a: ([case], manifest))
    # Explicitly an offline inventory stub; separate tests exercise the complete inventory gate.
    monkeypatch.setattr(cli, "execution_revision", lambda: ("offline-revision", "offline-code-hash"))
    return args(tmp_path, case["sample_id"]), calls


def test_actual_route_persists_original_evidence_and_private_sidecar(routed):
    options, calls = routed
    result = cli.run(options)
    assert len([c for c in calls if isinstance(c, tuple)]) == 1
    assert result["exit_status"] == 0
    assert result["status"] == "completed"
    assert result["execution_scope"] == "actual_llm_mcp"
    assert result["actual_model_calls"] is result["actual_sdk_calls"] is None
    assert result["elapsed_seconds"] > 0
    private = options.output_dir / "private"
    trial = TrialSidecar.model_validate_json((private / "trial_sidecar.json").read_text())
    mappings = json.loads((private / "runtime_identity_mappings.json").read_text())
    assert mappings == [b.model_dump(mode="json") for b in trial.observation.runtime_bindings]
    repo = SQLiteEvidenceRepository(private / "evidence.sqlite3")
    events = {e.event_id: e for identity in [trial.run_id, "runtime-run-1"]
              for e in repo.list_events_by_run(identity)}
    assert EvidenceView(trial, events.get).base_reason() is None
    original = SQLiteEvidenceRepository(calls[0][2] / "evidence.db")
    assert original.list_events_by_run("runtime-run-1") == repo.list_events_by_run("runtime-run-1")
    reports = options.output_dir / "reports" / "actual_llm_mcp"
    metadata = json.loads((reports / "run_metadata.json").read_text())
    assert metadata["execution_scope"] == metadata["label"] == "actual_llm_mcp"
    assert metadata["execution_config"]["seed"] is None
    assert metadata["model_configurations"][0]["request_timeout_seconds"] == 180
    assert metadata["actual_observations"][0]["observed_model_names"] == ["returned-model-version"] * 2
    with (reports / "trial_summary.csv").open(newline="") as f:
        row = next(csv.DictReader(f))
    assert row["run_status"] == "completed"
    assert json.loads(row["candidate_sdk_call_counts"]) == [1]
    assert "original-decision-id" in json.loads(row["evidence_refs"])
    assert trial.observation.semantic_outcomes.task.value is None


@pytest.mark.parametrize("mode,status", [("runtime_error", "error"), ("runtime_timeout", "timeout"), ("empty", "incomplete")])
def test_failure_records_are_preserved_without_retry(routed, backend_setup, monkeypatch, mode, status):
    options, _ = routed
    calls = install_runtime(monkeypatch, backend_setup, mode=mode)
    result = cli.run(options)
    assert result["exit_status"] == 1
    assert result["status"] == status
    assert len([c for c in calls if isinstance(c, tuple)]) == 1
    assert (options.output_dir / "private/trial_sidecar.json").is_file()
    metrics = json.loads((options.output_dir / "reports/actual_llm_mcp/metrics_summary.json").read_text())
    assert metrics["groups"][0]["rates"]["tsr_benign"]["denominator"] == 0


@pytest.mark.parametrize("extra", [
    ["--conditions", "A", "C"],
    ["--seed", "0"], ["--seed", "7"], ["--repeats", "2"], ["--sample-id", " "],
])
def test_actual_unsupported_configuration_rejected_before_inventory(tmp_path, monkeypatch, extra):
    monkeypatch.setattr(cli, "load_verified_cases", lambda *a: pytest.fail("must reject before dataset read"))
    with pytest.raises(ValueError):
        cli.run(args(tmp_path, "some-sample", *extra))
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("condition", ["A", "B", "C", "D"])
@pytest.mark.parametrize("scan", ["off", "on"])
def test_supported_conditions(tmp_path, condition, scan):
    cli.validate_options(args(tmp_path, "sample", "--conditions", condition, "--pi-t01", scan))


def test_validate_and_fixture_defaults_are_preserved(tmp_path):
    for operation, backend in [("validate", "mapping-only"), ("fixture", "fixture-replay")]:
        options = cli.parser().parse_args([
            operation, "--backend", backend, "--dataset-root", str(tmp_path),
            "--output-dir", str(tmp_path / "output"),
        ])
        cli.validate_options(options)
        assert options.seed == 0
        assert options.conditions == list("ABCD")
        options.sample_id = "sample"
        with pytest.raises(ValueError, match="only supported"):
            cli.validate_options(options)


def test_complete_inventory_validated_before_sample_selection(tmp_path, monkeypatch, inventory):
    cases, manifest = inventory
    candidate = tmp_path / "candidate.json"
    provenance = tmp_path / "provenance.json"
    candidate.write_text("{}")
    provenance.write_text(json.dumps(manifest))
    monkeypatch.setattr(cli, "CANDIDATE", candidate)
    monkeypatch.setattr(cli, "PROVENANCE", provenance)
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    (tmp_path / "benchmarks").mkdir()
    (tmp_path / "benchmarks/manifest.json").write_text("synthetic-hash")
    monkeypatch.setattr(cli.subprocess, "run", lambda command, **kw: SimpleNamespace(
        stdout=candidate.read_bytes() if "candidate.json" in command[-1] else provenance.read_bytes(),
    ))
    observed = []
    monkeypatch.setattr(cli, "load_bipia_candidates", lambda *a, **kw: cases[:10])
    monkeypatch.setattr(cli, "load_msb_candidates", lambda *a: cases[10:])
    original = cli.verify_inventory

    def verify(all_cases, manifest, previous):
        observed.append(len(all_cases))
        return original(all_cases, manifest, previous)

    monkeypatch.setattr(cli, "verify_inventory", verify)
    monkeypatch.setattr(cli, "execution_revision", lambda: ("test", "digest"))
    monkeypatch.setattr(cli, "actual_trial", lambda case, *a: {"selected": case["sample_id"]})
    options = args(tmp_path, cases[0]["sample_id"])
    options.output_dir = tmp_path.parent / (tmp_path.name + "-output")
    options.candidate_manifest, options.provenance_manifest = candidate, provenance
    assert cli.run(options)["selected"] == cases[0]["sample_id"]
    assert observed == [12]
    # Tamper an unselected MSB case: selecting BIPIA must not bypass its validation.
    cases[-1]["document_content"] += "changed"
    with pytest.raises(ValueError, match="hashes or provenance"):
        cli.run(options)
    assert observed == [12, 12]
    assert not options.output_dir.exists()


def test_unknown_sample_rejected_after_inventory(routed, monkeypatch):
    options, calls = routed
    options.sample_id = "not-an-inventory-id"
    with pytest.raises(ValueError, match="exactly one"):
        cli.run(options)
    assert not calls
    assert not options.output_dir.exists()


def test_report_privacy(routed, monkeypatch):
    from examples import run_agent_mcp_e2e as runtime

    options, _ = routed
    original = runtime.execute_agent_case
    marker = "PRIVATE_CONTENT_CREDENTIAL_MARKER"
    monkeypatch.setenv("LLM_API_KEY", marker)

    async def private_response(*a, **kw):
        raw = await original(*a, **kw)
        raw.final_response = marker
        raw.model_turns[-1].response_text = marker
        raw.tool_executions[0].tool_arguments["private"] = marker
        return raw

    monkeypatch.setattr(runtime, "execute_agent_case", private_response)
    cli.run(options)
    for path in (options.output_dir / "reports").rglob("*"):
        if path.is_file():
            assert marker not in path.read_text()
    assert marker not in (options.output_dir / "execution_summary.json").read_text()
    assert marker in (options.output_dir / "private/trial_sidecar.json").read_text()


def test_main_returns_actual_failure_exit_status(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "run", lambda args: {"exit_status": 1, "status": "timeout"})
    assert cli.main([
        "actual", "--backend", "actual-agent", "--dataset-root", str(tmp_path),
        "--output-dir", str(tmp_path / "out"),
    ]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "timeout"


def test_execution_revision_covers_actual_dependencies(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **kw: SimpleNamespace(stdout="baseline\n"))
    paths = [
        "src/runtime/test.py", "shared/test.py", "examples/run_agent_mcp_e2e.py",
        "examples/llm_openai_compatible.py", "src/security/policy/condition_configs/c_linked.yaml",
        "scripts/run_external_mcp_evaluation.py", "pyproject.toml", "uv.lock",
    ]
    for name in paths:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("original")
    baseline = cli.execution_revision()
    for name in paths:
        path = tmp_path / name
        path.write_text("changed")
        assert cli.execution_revision() != baseline, name
        path.write_text("original")


def test_runtime_events_without_scenario_remain_unverified(routed, monkeypatch):
    """Actual smoke exposed this contract gap; do not relax Evidence to hide it."""
    import sqlite3

    from examples import run_agent_mcp_e2e as runtime

    options, calls = routed
    original = runtime.execute_agent_case

    async def scenario_missing(*a, **kw):
        raw = await original(*a, **kw)
        with sqlite3.connect(raw.evidence_db_path) as con:
            con.execute("UPDATE security_events SET scenario_id = NULL")
        return raw

    monkeypatch.setattr(runtime, "execute_agent_case", scenario_missing)
    result = cli.run(options)
    assert result["exit_status"] == 1
    assert result["status"] == "error"
    assert result["evidence_validated"] is False
    assert len([c for c in calls if isinstance(c, tuple)]) == 1
    trial = TrialSidecar.model_validate_json((options.output_dir / "private/trial_sidecar.json").read_text())
    assert trial.observation.candidates[0].tool_executed is True
    assert trial.observation.error_detail == "ValueError"
    assert "runtime_binding_link_unverified" in trial.evidence_issues
    assert trial.observation.semantic_outcomes.task.value is None
    events = SQLiteEvidenceRepository(calls[0][2] / "evidence.db").list_events_by_run("runtime-run-1")
    assert len(events) == 2
    assert all(e.scenario_id is None for e in events)


def test_actual_d_on_routes_to_runtime(routed):
    options, calls = routed
    options.conditions = ["D"]
    options.pi_t01 = "on"
    result = cli.run(options)
    assert result["exit_status"] == 0
    assert calls[0][1].condition == "D"
    assert calls[0][1].output_injection_scan is True
    trial = TrialSidecar.model_validate_json((options.output_dir / "private/trial_sidecar.json").read_text())
    assert trial.output_injection_scan is True
    assert "+pit01" in trial.policy_version


def test_actual_scenario_anchor_accepts_legacy_security_envelopes(routed, monkeypatch):
    import sqlite3

    from schemas.evidence import SecurityEvent

    from examples import run_agent_mcp_e2e as runtime

    options, _ = routed
    original = runtime.execute_agent_case

    async def anchored(*a, **kw):
        raw = await original(*a, **kw)
        item = raw.tool_executions[0]
        with sqlite3.connect(raw.evidence_db_path) as con:
            con.execute("UPDATE security_events SET scenario_id = NULL")
        repo = SQLiteEvidenceRepository(raw.evidence_db_path)
        repo.save_event(SecurityEvent(
            event_id="original-runtime-anchor", run_id=item.run_id, trace_id=item.trace_id,
            scenario_id=raw.scenario_id, event_type="RUNTIME_OBSERVATION",
            payload={"run_id": item.run_id, "trace_id": item.trace_id, "scenario_id": raw.scenario_id},
        ))
        item.record_evidence(repo.list_events_by_run(item.run_id))
        return raw

    monkeypatch.setattr(runtime, "execute_agent_case", anchored)
    result = cli.run(options)
    assert result["exit_status"] == 0
    assert result["evidence_validated"] is True
    trial = TrialSidecar.model_validate_json((options.output_dir / "private/trial_sidecar.json").read_text())
    repo = SQLiteEvidenceRepository(options.output_dir / "private/evidence.sqlite3")
    events = {e.event_id: e for run in [trial.run_id, "runtime-run-1"] for e in repo.list_events_by_run(run)}
    assert EvidenceView(trial, events.get).base_reason() is None
    assert events["original-decision-id"].scenario_id is None
    assert events["original-result-id"].scenario_id is None
    assert trial.observation.semantic_outcomes.task.value is None
