"""Entirely synthetic reviewed packages; no received data is embedded here."""

import io
import json
import stat
import sys
import zipfile
from copy import deepcopy
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from demo.benchmark_reader import load_holdout, load_tuning
from demo.reviewed_package import (
    EXPECTED,
    digest,
    import_archive,
    json_object,
    read_archive,
    validate_directory,
)
from scripts.verify_holdout_raw import verify_raw
from tests.unit.test_plot_holdout_aggregates import _csv
from tests.unit.test_verify_holdout_raw import fixture_files


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


def seal(files, originals):
    files = dict(files)
    entries = [
        {
            "path": name,
            "sha256": digest(blob),
            "source": "synthetic-source/" + name,
            "source_sha256": digest(originals.get(name, blob)),
            "modified": blob != originals.get(name, blob),
        }
        for name, blob in sorted(files.items())
        if name not in ("SHA256SUMS.txt", "PACKAGE_MANIFEST.json")
    ]
    manifest = {
        "runtime_execution_verified": False,
        "tensor_trust_rights": "unresolved",
        "redistribution_permission_confirmed": False,
        "original_for_wana_zip_sha256": digest(b"synthetic-original-archive"),
        "transformations": ["Synthetic privacy metadata omitted; aggregates preserved"],
        "files": entries,
    }
    files["PACKAGE_MANIFEST.json"] = encoded(manifest)
    files["SHA256SUMS.txt"] = "".join(
        digest(blob) + "  " + name + "\n"
        for name, blob in sorted(files.items())
        if name != "SHA256SUMS.txt"
    ).encode()
    return files


def synthetic_package():
    source = fixture_files()
    data = json.loads(source["holdout_results.json"])
    data.update(headline_block_threshold=0.8, tool_policy={}, notes=[])
    source["holdout_results.json"] = encoded(data)
    record = json.loads(source["run_record_holdout.json"])
    record["policy"].update(headline_block_threshold=0.8, tool_policy_policy_run={})
    record["commands"] = ["synthetic omitted command"]
    source["run_record_holdout.json"] = encoded(record)
    raw = verify_raw(source)
    raw["source_archive_sha256"] = digest(b"synthetic-original-archive")
    files = {
        name: b"Synthetic package notes"
        for name in EXPECTED
        if name not in ("PACKAGE_MANIFEST.json", "SHA256SUMS.txt")
    }
    for name in (
        "holdout_results.json",
        "run_record_holdout.json",
        "sweep_holdout_summary.csv",
        "sweep_policy_holdout_summary.csv",
        "c_cause_holdout.csv",
    ):
        files["holdout/" + name] = source[name]
    # A valid one-pixel PNG is enough to exercise Streamlit's image pipeline.
    from PIL import Image

    stream = io.BytesIO()
    Image.new("RGB", (2, 2), (20, 80, 140)).save(stream, format="PNG")
    for name in files:
        if name.endswith(".png"):
            files[name] = stream.getvalue()
        elif name.endswith(".svg"):
            files[name] = (
                b'<svg xmlns="http://www.w3.org/2000/svg" width="2" height="2"/>'
            )
    raw["figure_sha256"] = {
        Path(name).name: digest(blob)
        for name, blob in files.items()
        if name.startswith("holdout/figures/") and name.endswith((".png", ".svg"))
    }
    files["holdout/raw_verification.json"] = encoded(raw)
    metadata = {
        "status": "raw_arithmetic_verified",
        "runtime_execution_verified": False,
        "input_sha256": raw["input_sha256"],
        "figure_sha256": raw["figure_sha256"],
        "source_archive_sha256": raw["source_archive_sha256"],
        "raw_verification_report_sha256": digest(
            files["holdout/raw_verification.json"]
        ),
    }
    files["holdout/figures/aggregate_validation.json"] = encoded(metadata)
    latency = [
        {"condition": m, "n": 1, "mean_ms": 0.1, "p50_ms": 0.1, "p95_ms": 0.1}
        for m in "ABC"
    ]
    detection = [
        {
            "dataset": "synthetic",
            "subset": "s",
            "label": "benign",
            "guard": "input",
            "n": 1,
            "flagged": 0,
            "rate": 0.0,
        }
    ]
    cells = raw["sweeps"]["default"]["cells"]
    tuning = {
        "schema_version": "imported-fatin-audit-v1",
        "status": "arithmetic_audited",
        "split": "tune",
        "evidence_validated": False,
        "summary_mismatches": [],
        "cells": cells,
        "latency": latency,
        "guard_detection": detection,
        "raw_trial_rows": 102,
        "input_sha256": {
            "results/sweep_bc_tune_trials.csv": digest(b"synthetic tuning trials"),
            "results/sweep_bc_tune_summary.csv": digest(b"synthetic tuning summary"),
        },
    }
    files["tuning/audit_summary.json"] = encoded(tuning)
    files["tuning/core_latency.csv"] = _csv(latency)
    files["tuning/guard_detection.csv"] = _csv(detection)
    files["tuning/recomputed_sweep.csv"] = _csv(cells)
    plot = {
        "split": "tune",
        "toolpolicy": "absent",
        "cells": cells,
        "input_sha256": {
            "sweep_bc_tune_trials.csv": tuning["input_sha256"][
                "results/sweep_bc_tune_trials.csv"
            ],
            "sweep_bc_tune_summary.csv": tuning["input_sha256"][
                "results/sweep_bc_tune_summary.csv"
            ],
            "core_latency.csv": digest(files["tuning/core_latency.csv"]),
        },
    }
    files["tuning/plot_audit.json"] = encoded(plot)
    files["package_review.json"] = encoded(
        {
            "runtime_execution_verified": False,
            "redistribution_permission_confirmed": False,
        }
    )
    originals = deepcopy(files)
    metadata["original_raw_verification_report_sha256"] = digest(
        originals["holdout/raw_verification.json"]
    )
    for name in (
        "holdout/holdout_results.json",
        "holdout/run_record_holdout.json",
        "holdout/raw_verification.json",
        "tuning/audit_summary.json",
        "tuning/plot_audit.json",
    ):
        value = json.loads(files[name])
        value["runtime_execution_verified"] = False
        value["handoff_notice"] = "Synthetic reviewed copy; original bytes omitted"
        value.pop("commands", None)
        files[name] = encoded(value)
    metadata["raw_verification_report_sha256"] = digest(
        files["holdout/raw_verification.json"]
    )
    metadata["handoff_notice"] = "Synthetic review metadata"
    files["holdout/figures/aggregate_validation.json"] = encoded(metadata)
    return seal(files, originals), originals


def archive(tmp_path, files, name="handoff.zip"):
    path = tmp_path / name
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for filename, blob in files.items():
            z.writestr(filename, blob)
    return path


def test_reviewed_source_and_current_hashes_are_distinct_and_reader_works(tmp_path):
    files, _ = synthetic_package()
    root = tmp_path / "local"
    proof = import_archive(archive(tmp_path, files), root)
    assert proof["file_count"] == 34
    report = load_holdout(root / "holdout")
    assert not report["errors"], report["errors"]
    assert len(report["figures"]) == 4
    assert report["package"]["raw_trial_recalculation_performed_here"] is False
    entry = proof["entries"]["holdout/holdout_results.json"]
    assert entry["source_sha256"] != entry["sha256"]
    assert (
        report["raw"]["input_sha256"]["holdout_results.json"] == entry["source_sha256"]
    )
    assert (
        digest((root / "holdout/holdout_results.json").read_bytes()) == entry["sha256"]
    )
    assert len(load_tuning(root / "tuning")["figures"]) == 4
    assert import_archive(tmp_path / "handoff.zip", root)["hashes"] == proof["hashes"]


@pytest.mark.parametrize(
    "name",
    [
        "../outside",
        "C:/outside",
        "holdout\\outside",
        "/absolute",
        "holdout/CON.txt",
        "holdout/x.",
        "holdout/../outside",
        "holdout//x",
        "holdout/x:stream",
    ],
)
def test_unsafe_members_rejected_before_extraction(tmp_path, name):
    path = archive(tmp_path, {name: b"unsafe"})
    with pytest.raises(ValueError):
        import_archive(path, tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_duplicate_case_collision_and_symlink_rejected(tmp_path):
    for mode in ("duplicate", "case", "link"):
        path = tmp_path / (mode + ".zip")
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("README.md", b"a")
            if mode == "link":
                i = zipfile.ZipInfo("linked")
                i.create_system = 3
                i.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(i, b"../target")
            elif mode == "duplicate":
                with pytest.warns(UserWarning, match="Duplicate name"):
                    z.writestr("README.md", b"b")
            else:
                z.writestr("readme.MD", b"b")
        with pytest.raises(ValueError):
            read_archive(path)


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "unexpected",
        "hash",
        "manifest",
        "source",
        "runtime",
        "tuning_cells",
        "tuning_latency",
        "tuning_guard",
        "split",
    ],
)
def test_missing_tampered_or_semantically_inconsistent_packages_rejected(
    tmp_path, change
):
    files, originals = synthetic_package()
    if change == "missing":
        del files["tuning/figures/direct_indirect.png"]
    elif change == "unexpected":
        files["unexpected.txt"] = b"x"
    elif change == "hash":
        files["holdout/sweep_holdout_summary.csv"] += b"changed"
    elif change == "manifest":
        m = json.loads(files["PACKAGE_MANIFEST.json"])
        m["files"][0]["sha256"] = "0" * 64
        files["PACKAGE_MANIFEST.json"] = encoded(m)
        files["SHA256SUMS.txt"] = "".join(
            digest(b) + "  " + n + "\n"
            for n, b in sorted(files.items())
            if n != "SHA256SUMS.txt"
        ).encode()
    else:
        if change == "source":
            raw = json.loads(files["holdout/raw_verification.json"])
            raw["input_sha256"]["holdout_results.json"] = "0" * 64
            files["holdout/raw_verification.json"] = encoded(raw)
        elif change == "runtime":
            v = json.loads(files["tuning/audit_summary.json"])
            v["runtime_execution_verified"] = True
            files["tuning/audit_summary.json"] = encoded(v)
        elif change == "tuning_cells":
            v = json.loads(files["tuning/plot_audit.json"])
            v["cells"][1]["n_attack"] = 99
            files["tuning/plot_audit.json"] = encoded(v)
        elif change == "tuning_latency":
            files["tuning/core_latency.csv"] = files["tuning/core_latency.csv"].replace(
                b"0.1", b"0.2"
            )
        elif change == "tuning_guard":
            files["tuning/guard_detection.csv"] = files[
                "tuning/guard_detection.csv"
            ].replace(b",0,", b",1,")
        elif change == "split":
            v = json.loads(files["tuning/plot_audit.json"])
            v["split"] = "holdout"
            files["tuning/plot_audit.json"] = encoded(v)
        files = seal(files, originals)
    path = archive(tmp_path, files)
    try:
        import_archive(path, tmp_path / "out")
    except (ValueError, KeyError, TypeError):
        return
    h = load_holdout(tmp_path / "out/holdout")
    if h["errors"]:
        return
    with pytest.raises((ValueError, KeyError, TypeError)):
        load_tuning(tmp_path / "out/tuning")


def test_post_import_mutation_and_existing_destination_are_rejected(tmp_path):
    files, _ = synthetic_package()
    source = archive(tmp_path, files)
    root = tmp_path / "out"
    import_archive(source, root)
    (root / "tuning/core_latency.csv").write_bytes(b"changed")
    with pytest.raises(ValueError):
        validate_directory(root)
    with pytest.raises(ValueError):
        import_archive(source, root)
    assert load_holdout(root / "holdout")["errors"]


def test_json_duplicate_keys_and_nonfinite_values_are_rejected():
    for blob in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'):
        with pytest.raises(ValueError):
            json_object(blob)
