"""Offline reporting/CLI contracts; synthetic inputs only, no actual evaluation."""

import asyncio
import csv
import json
from copy import deepcopy

import pytest

from evaluation.external_mcp_adapter import build_bipia_pair
from evaluation.external_mcp_cli import (
    fixture_trials,
    main,
    parser,
    validate_options,
    verify_inventory,
)
from evaluation.external_mcp_judges import judge_trial
from evaluation.external_mcp_metrics import aggregate_external
from evaluation.external_mcp_plots import render_graphs
from evaluation.external_mcp_report import FIXTURE_LABEL, write_reports
from evaluation.mcp_external_manifest import (
    BIPIA_PROVENANCE_FIELDS,
    MSB_PROVENANCE_FIELDS,
    build_manifest,
)
from evaluation.msb_mcp_adapter import build_msb_pair
from tests.unit import test_external_mcp_phase2 as phase2

lab = phase2.lab
judged = phase2.judged


@pytest.fixture
def inventory():
    cases = []
    for i in range(5):
        provenance = dict.fromkeys(BIPIA_PROVENANCE_FIELDS, "synthetic-hash")
        provenance.update(pair_id=f"test-pair-{i}", dataset_id="bipia")
        cases.extend(build_bipia_pair(
            {"context": f"Synthetic table {i}", "question": "Synthetic question?", "ideal": str(i)},
            "Synthetic reversal variant", provenance,
        ))
    provenance = dict.fromkeys(MSB_PROVENANCE_FIELDS, "synthetic-hash")
    provenance["dataset_id"] = "msb"
    cases.extend(build_msb_pair("Synthetic template {goal}", provenance))
    return cases, build_manifest(cases, "synthetic-hash")


def cli_args(tmp_path, operation="fixture", backend="fixture-replay", *extra):
    return parser().parse_args([
        operation, "--backend", backend, "--dataset-root", str(tmp_path / "data"),
        "--output-dir", str(tmp_path / "output"), *extra,
    ])


def test_guard_fpr_labels_and_overlapping_warn_block(lab):
    from enums import Decision
    t, _, _ = lab[0](classification="benign", decision="BLOCK")
    c = t.observation.candidates[0]
    warn = c.guard_results[0].model_copy(deep=True)
    warn.decision = Decision.WARN
    c.guard_results.insert(0, warn)
    c.warn = True
    c.evidence_refs.append(lab[2](t, "SECURITY_RESULT", warn.model_dump(mode="json")))
    rates = aggregate_external([t], lab[1].get)["groups"][0]["rates"]
    for name in ("guard_warn_or_block_fpr", "benign_guard_block", "benign_guard_warn"):
        assert rates[name]["numerator"] == rates[name]["denominator"] == 1
    assert rates["fpr"]["label"] == "Guard WARN-or-BLOCK FPR"


def preexposure(lab, dataset="bipia"):
    t, case, review = lab[0](dataset=dataset)
    t.observation.candidates.clear()
    t.observation.payload_exposure_refs = []
    t.observation.model_response_refs = []
    t.observation.model_tool_selection_observed = None
    t.observation.candidate_trace_complete = None
    exposure = lab[2](t, "EXPOSURE_AUDIT", {"complete": True, "exposed_to_model": False})
    if dataset == "bipia":
        absence = lab[2](t, "FINAL_RESPONSE_AUDIT", {"complete": True, "attack_output_delivered": False})
    else:
        from evaluation.external_mcp_judges import MSB_DESTINATION, MSB_MARKER
        absence = lab[2](t, "SIMULATED_SINK_AUDIT", {
            "complete": True, "simulated": True, "destination": MSB_DESTINATION,
            "marker": MSB_MARKER, "matching_transfer_event_ids": [],
        })
        t.observation.evidence_refs.append(absence)
    audit = lab[2](t, "ATTACK_OUTCOME_AUDIT", {
        "complete": True, "objective_achieved": False, "exposure_prevented": True,
        "reviewer": "synthetic-reviewer", "mapped_case_sha256": t.mapped_case_sha256,
        "supporting_evidence_refs": [exposure, absence],
    })
    return t, case, review, audit


@pytest.mark.parametrize("dataset", ["bipia", "msb"])
def test_end_to_end_includes_verified_preexposure_failure(lab, dataset):
    t, case, review, audit = preexposure(lab, dataset)
    t = judge_trial(t, case, lab[1].get, rule_review_ref=review, pre_exposure_audit_ref=audit)
    rates = aggregate_external([t], lab[1].get)["groups"][0]["rates"]
    assert rates["asr_end_to_end"]["denominator"] == 1
    assert rates["asr_end_to_end"]["rate"] == 0
    assert rates["asr_exposure_conditioned"]["denominator"] == 0
    assert rates["asr_exposure_conditioned"]["rate"] is None
    assert rates["asr_end_to_end"]["attempted_attack_trials"] == 1


@pytest.mark.parametrize("defect", ["missing", "incomplete", "unreviewed", "unproven_absence", "timeout"])
def test_preexposure_failure_requires_independent_complete_audit(lab, defect):
    t, case, review, audit = preexposure(lab)
    event = lab[1][audit]
    if defect == "missing":
        lab[1].pop(audit)
    elif defect == "incomplete":
        event.payload["complete"] = False
    elif defect == "unreviewed":
        event.payload["reviewer"] = None
    elif defect == "unproven_absence":
        event.payload["supporting_evidence_refs"].pop()
    else:
        t.observation.run_status = "timeout"
    t = judge_trial(t, case, lab[1].get, rule_review_ref=review, pre_exposure_audit_ref=audit)
    assert t.observation.semantic_outcomes.attack.value is None


def test_block_alone_is_not_end_to_end_attack_failure(lab):
    t, case, review = lab[0](decision="BLOCK", response="ambiguous")
    t.observation.payload_exposure_refs = []
    t = judge_trial(t, case, lab[1].get, rule_review_ref=review)
    rates = aggregate_external([t], lab[1].get)["groups"][0]["rates"]
    assert rates["asr_end_to_end"]["denominator"] == 0


def test_report_json_csv_schema_and_missing_values(lab, tmp_path):
    t = judged(lab, reference="2", response="2")
    bundle = write_reports([t], lab[1].get, tmp_path / "reports")[0]
    root = bundle["directory"]
    assert set(bundle["metadata"]["files"]) == {p.name for p in root.iterdir()}
    with (root / "metrics_summary.csv").open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    metrics = json.loads((root / "metrics_summary.json").read_text(encoding="utf-8"))
    asr = next(r for r in rows if r["metric"] == "asr_end_to_end")
    assert asr["rate"] == ""
    assert metrics["groups"][0]["rates"]["asr_end_to_end"]["rate"] is None
    assert int(asr["denominator"]) == 0
    assert json.loads(asr["exclusion_reasons"]) == metrics["groups"][0]["rates"]["asr_end_to_end"]["exclusion_reasons"]
    assert (root / "cd_comparison.csv").read_text().strip()


def test_export_privacy_allowlist(lab, tmp_path):
    secret = "PRIVATE_RAW_MARKER_DO_NOT_EXPORT"
    t = judged(lab)
    t.model["api_key"] = secret
    t.model["system_prompt"] = secret
    t.provenance["document_content"] = secret
    t.observation.candidates[0].requested_tool.arguments["private"] = secret
    t.observation.semantic_outcomes.attack.reason = secret
    t.observation.semantic_outcomes.attack.value = None
    for event in lab[1].values():
        if event.event_type == "MODEL_RESPONSE":
            event.payload["text"] = secret
    bundles = write_reports([t], lab[1].get, tmp_path / "reports", execution_config={"api_key": secret})
    for file in bundles[0]["directory"].iterdir():
        assert secret not in file.read_text(encoding="utf-8")


def test_scope_separated_outputs_and_no_overwrite(lab, tmp_path):
    rows = [judged(lab), judged(lab, scope="fixture_execution")]
    output = tmp_path / "reports"
    bundles = write_reports(rows, lab[1].get, output)
    assert {b["directory"].name for b in bundles} == {"actual_llm_mcp", "fixture_execution"}
    fixture = next(b for b in bundles if b["directory"].name == "fixture_execution")
    assert fixture["metadata"]["label"] == FIXTURE_LABEL
    with pytest.raises(ValueError, match="empty"):
        write_reports(rows, lab[1].get, output)


@pytest.mark.parametrize("change", ["case", "inventory", "hash", "freeze"])
def test_mapping_mismatches_rejected(inventory, change):
    cases, manifest = deepcopy(inventory)
    if change == "case":
        cases[0]["document_content"] += "tampered"
    elif change == "inventory":
        cases.pop()
    elif change == "hash":
        manifest["samples"][0]["mapped_case_sha256"] = "tampered"
    else:
        manifest["selection_frozen"] = True
    with pytest.raises(ValueError):
        verify_inventory(cases, manifest, "synthetic-hash")


@pytest.mark.parametrize("extra", [
    ["--repeats", "0"], ["--timeout", "0"], ["--timeout", "nan"],
    ["--conditions", "C", "C"], ["--experiment-id", " "],
])
def test_cli_configuration_validation(tmp_path, extra):
    args = cli_args(tmp_path, "fixture", "fixture-replay", *extra)
    with pytest.raises(ValueError):
        validate_options(args)


def test_actual_execution_explicitly_rejected_before_dataset_reads(tmp_path, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("unavailable actual execution must fail before dataset access")
    monkeypatch.setattr("evaluation.external_mcp_cli.load_verified_cases", forbidden)
    with pytest.raises(SystemExit) as exc:
        main(["actual", "--backend", "actual-agent", "--dataset-root", str(tmp_path),
              "--output-dir", str(tmp_path / "actual")])
    assert exc.value.code == 2
    assert "no fixture substitution" in capsys.readouterr().err
    assert not (tmp_path / "actual").exists()


def test_backend_mismatch_and_repository_output_rejected(tmp_path):
    with pytest.raises(ValueError, match="mismatch"):
        validate_options(cli_args(tmp_path, "actual", "fixture-replay"))
    from evaluation.external_mcp_cli import ROOT
    args = cli_args(tmp_path)
    args.output_dir = ROOT / "reports/phase3"
    with pytest.raises(ValueError, match="outside"):
        validate_options(args)


def test_fixture_48_trials_and_reproducible_exports(inventory, tmp_path):
    cases, manifest = inventory
    args = cli_args(tmp_path)
    first, backend = asyncio.run(fixture_trials(cases, manifest, args, "test-revision"))
    second, backend2 = asyncio.run(fixture_trials(cases, manifest, args, "test-revision"))
    assert len(first) == 48
    assert {t.condition for t in first} == set("ABCD")
    assert all(t.observation.run_status == "completed" for t in first)
    assert all(t.policy_version.startswith("fixture-simulated-") for t in first)
    assert all(t.observation.attack_objective_achieved is None for t in first)
    a = write_reports(first, backend.events.get, tmp_path / "first")[0]["directory"]
    b = write_reports(second, backend2.events.get, tmp_path / "second")[0]["directory"]
    for path in a.iterdir():
        assert path.read_bytes() == (b / path.name).read_bytes()


def test_graphs_preserve_missing_results_and_fixture_label(lab, tmp_path):
    t = judged(lab, scope="fixture_execution")
    bundle = write_reports([t], lab[1].get, tmp_path / "reports")[0]
    files = render_graphs(bundle, lab[1].get)
    assert len(files) == 10
    svg = next(path for path in files if path.name.startswith("semantic_rates") and path.suffix == ".svg")
    text = svg.read_text(encoding="utf-8")
    assert FIXTURE_LABEL in text and "Unavailable" in text and "n=0" in text
    assert all(path.stat().st_size > 100 for path in files)


def test_actual_graphs_require_actual_completed_observations(lab, tmp_path):
    t = judged(lab)
    t.observation.run_status = "incomplete"
    bundle = write_reports([t], lab[1].get, tmp_path / "reports")[0]
    assert render_graphs(bundle, lab[1].get) == []


def test_verified_success_without_exposure_log_is_end_to_end_only(lab):
    t = judged(lab, response="snaeb kcalb")
    t.observation.payload_exposure_refs = []
    rates = aggregate_external([t], lab[1].get)["groups"][0]["rates"]
    assert rates["asr_end_to_end"]["rate"] == 1
    assert rates["asr_exposure_conditioned"]["rate"] is None


def test_code_revisions_are_not_pooled(lab):
    a, b = judged(lab), judged(lab)
    b.code_revision = "different-revision"
    assert len(aggregate_external([a, b], lab[1].get)["groups"]) == 2


def test_source_line_endings_are_not_silently_normalized(tmp_path):
    from evaluation.external_mcp_adapter import sha256, verify_file
    path = tmp_path / "source.txt"
    pinned = b"synthetic\r\nsource\r\n"
    path.write_bytes(pinned.replace(b"\r\n", b"\n"))
    with pytest.raises(ValueError, match="hash mismatch"):
        verify_file(path, sha256(pinned))


def test_candidate_manifest_mismatch_rejected_before_source_access(tmp_path):
    from evaluation.external_mcp_cli import load_verified_cases
    candidate = tmp_path / "candidate.json"
    candidate.write_text('{"changed": true}', encoding="utf-8")
    with pytest.raises(ValueError, match="candidate manifest differs"):
        load_verified_cases(tmp_path / "does-not-exist", candidate_manifest=candidate)


def test_cd_csv_columns_do_not_depend_on_pair_availability(lab, tmp_path):
    from evaluation.external_mcp_report import CD_FIELDS
    for index, rows in enumerate((
        [judged(lab, condition="A")],
        [judged(lab, condition="C"), judged(lab, condition="D")],
    )):
        bundle = write_reports(rows, lab[1].get, tmp_path / str(index))[0]
        with (bundle["directory"] / "cd_comparison.csv").open(newline="", encoding="utf-8") as f:
            assert tuple(csv.DictReader(f).fieldnames) == CD_FIELDS


def test_fixture_graph_files_are_reproducible(lab, tmp_path):
    trial = judged(lab, scope="fixture_execution")
    first = write_reports([trial], lab[1].get, tmp_path / "first")[0]
    second = write_reports([trial], lab[1].get, tmp_path / "second")[0]
    a = render_graphs(first, lab[1].get)
    b = render_graphs(second, lab[1].get)
    assert [p.name for p in a] == [p.name for p in b]
    assert all(left.read_bytes() == right.read_bytes() for left, right in zip(a, b, strict=True))
