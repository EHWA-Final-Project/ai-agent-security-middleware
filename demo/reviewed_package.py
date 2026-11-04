"""Validate a reviewed handoff without rewriting historical hashes or payloads.

Checksums are consistency evidence, not a signature or redistribution permission.
Original bytes are absent: source relationships remain supplied declarations.
"""

import hashlib
import json
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath

HOLDOUT_FIGURES = (
    "holdout_attack_tool_execution",
    "holdout_benign_outcomes",
    "holdout_tool_policy",
    "holdout_c_block_causes",
)
TUNING_FIGURES = (
    "attack_tool_execution",
    "benign_warn_block",
    "core_latency",
    "direct_indirect",
)
EXPECTED = {
    "PACKAGE_MANIFEST.json",
    "SHA256SUMS.txt",
    "README.md",
    "package_review.json",
    "holdout/holdout_results.json",
    "holdout/run_record_holdout.json",
    "holdout/raw_verification.json",
    "holdout/sweep_holdout_summary.csv",
    "holdout/sweep_policy_holdout_summary.csv",
    "holdout/c_cause_holdout.csv",
    "holdout/figures/aggregate_validation.json",
    "holdout/figures/POSTER_GRAPH_NOTES.md",
    "tuning/audit_summary.json",
    "tuning/plot_audit.json",
    "tuning/recomputed_sweep.csv",
    "tuning/guard_detection.csv",
    "tuning/core_latency.csv",
    "tuning/figures/TUNING_GRAPH_NOTES_KR.md",
} | {
    f"{split}/figures/{name}{suffix}"
    for split, names in (("holdout", HOLDOUT_FIGURES), ("tuning", TUNING_FIGURES))
    for name in names
    for suffix in (".png", ".svg")
}
HEX = re.compile(r"[0-9a-f]{64}\Z")
RESERVED = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def safe_name(name):
    if (
        not isinstance(name, str)
        or not name
        or "\\" in name
        or ":" in name
        or name.startswith("/")
        or any(
            ord(c) < 32 or c in "\u202a\u202b\u202d\u202e\u2066\u2067\u2068\u2069"
            for c in name
        )
    ):
        raise ValueError("unsafe package path")
    parts = name.split("/")
    if any(
        p in ("", ".", "..")
        or p.endswith((" ", "."))
        or p.split(".")[0].casefold() in RESERVED
        for p in parts
    ):
        raise ValueError("unsafe package path component")
    return name


def json_object(blob):
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError("duplicate JSON key")
            result[k] = v
        return result

    def invalid_constant(value):
        raise ValueError(f"invalid JSON number: {value}")

    result = json.loads(
        blob.decode("utf-8-sig"),
        object_pairs_hook=pairs,
        parse_constant=invalid_constant,
    )
    if not isinstance(result, dict):
        raise TypeError("expected package JSON object")
    return result


def validate_payload(files):
    if set(files) != EXPECTED:
        raise ValueError(
            f"package inventory differs: missing={sorted(EXPECTED - files.keys())}, unexpected={sorted(files.keys() - EXPECTED)}"
        )
    hashes = {name: digest(blob) for name, blob in files.items()}
    sums = {}
    for line in files["SHA256SUMS.txt"].decode("utf-8-sig").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise ValueError("malformed SHA256SUMS entry")
        value, name = match.groups()
        safe_name(name)
        if name in sums:
            raise ValueError("duplicate checksum path")
        sums[name] = value
    if set(sums) != set(files) - {"SHA256SUMS.txt"} or any(
        hashes[n] != v for n, v in sums.items()
    ):
        raise ValueError("SHA256SUMS mismatch or incomplete coverage")
    manifest = json_object(files["PACKAGE_MANIFEST.json"])
    if (
        manifest.get("runtime_execution_verified") is not False
        or manifest.get("redistribution_permission_confirmed") is not False
        or manifest.get("tensor_trust_rights") != "unresolved"
    ):
        raise ValueError("unsupported package scope / rights state")
    transformations = manifest["transformations"]
    if not isinstance(transformations, list) or not all(
        isinstance(s, str) and s for s in transformations
    ):
        raise TypeError("expected declared transformations")
    entries = {}
    for entry in manifest["files"]:
        name = safe_name(entry["path"])
        if name in entries or name not in files:
            raise ValueError("duplicate or unexpected manifest path")
        if not HEX.fullmatch(entry["source_sha256"]) or hashes[name] != entry["sha256"]:
            raise ValueError("manifest file SHA256 mismatch")
        if (
            not isinstance(entry["modified"], bool)
            or not isinstance(entry["source"], str)
            or not entry["source"]
        ):
            raise TypeError("invalid transformation declaration")
        differs = entry["source_sha256"] != entry["sha256"]
        if differs != entry["modified"] or (differs and not transformations):
            raise ValueError("undeclared or inconsistent transformation")
        if differs and name not in {
            "holdout/holdout_results.json",
            "holdout/run_record_holdout.json",
            "holdout/raw_verification.json",
            "holdout/figures/aggregate_validation.json",
            "tuning/audit_summary.json",
            "tuning/plot_audit.json",
        }:
            raise ValueError("unexpected transformation of an aggregate or graph")
        entries[name] = entry
    if set(entries) != set(files) - {"PACKAGE_MANIFEST.json", "SHA256SUMS.txt"}:
        raise ValueError("manifest coverage mismatch")
    review = json_object(files["package_review.json"])
    if (
        review.get("runtime_execution_verified") is not False
        or review.get("redistribution_permission_confirmed") is not False
    ):
        raise ValueError("unsupported review scope")
    for name in (
        "holdout/holdout_results.json",
        "holdout/run_record_holdout.json",
        "holdout/raw_verification.json",
        "holdout/figures/aggregate_validation.json",
        "tuning/audit_summary.json",
        "tuning/plot_audit.json",
    ):
        if json_object(files[name]).get("runtime_execution_verified") is not False:
            raise ValueError(
                f"package file claims unsupported Runtime verification: {name}"
            )
    return {
        "status": "review_package_integrity_checked",
        "file_count": len(files),
        "hashes": hashes,
        "entries": entries,
        "transformations": transformations,
        "original_archive_sha256": manifest["original_for_wana_zip_sha256"],
        "runtime_execution_verified": False,
        "raw_trial_recalculation_performed_here": False,
        "original_pre_redaction_json_bytes_available": False,
        "redistribution_permission_confirmed": False,
        "limitations": [
            "Unsigned package: hashes check consistency, not authenticity.",
            "Source hashes and redactions are declared provenance; original bytes are absent.",
            "Historical raw arithmetic status is not a new raw-trial or Runtime verification.",
        ],
    }


def read_archive(source):
    source = Path(source)
    files, seen, total = {}, set(), 0
    if source.stat().st_size > MAX_TOTAL:
        raise ValueError("archive too large")
    with zipfile.ZipFile(source) as archive:
        if len(archive.infolist()) > 128:
            raise ValueError("too many archive members")
        for info in archive.infolist():
            name = safe_name(
                info.filename.rstrip("/") if info.is_dir() else info.filename
            )
            if name.casefold() in seen:
                raise ValueError("duplicate or case-colliding archive member")
            seen.add(name.casefold())
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode) or (
                stat.S_IFMT(mode) and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))
            ):
                raise ValueError("archive links / special files are forbidden")
            if info.flag_bits & 1 or info.file_size > MAX_FILE:
                raise ValueError("encrypted or oversized archive member")
            if info.is_dir():
                if not any(n.startswith(name + "/") for n in EXPECTED):
                    raise ValueError("unexpected archive directory")
                continue
            total += info.file_size
            if name not in EXPECTED or total > MAX_TOTAL:
                raise ValueError("unexpected or oversized package")
            files[name] = archive.read(info)
    proof = validate_payload(files)
    proof["zip_sha256"] = digest(source.read_bytes())
    return files, proof


def validate_directory(root):
    root = Path(root)
    if root.is_symlink():
        raise ValueError("symlink package root")
    files = {}
    total = 0
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("symlink in package directory")
        if path.is_file():
            name = safe_name(path.relative_to(root).as_posix())
            total += path.stat().st_size
            if (
                name not in EXPECTED
                or path.stat().st_size > MAX_FILE
                or total > MAX_TOTAL
            ):
                raise ValueError("unexpected or oversized extracted file")
            files[name] = path.read_bytes()
    return validate_payload(files)


def import_archive(source, destination):
    files, proof = read_archive(source)
    destination = Path(destination).absolute()
    if any(p.is_symlink() for p in (destination, *destination.parents)):
        raise ValueError("symlink extraction destination")
    if destination.exists():
        current = validate_directory(destination)
        if current["hashes"] != proof["hashes"]:
            raise ValueError("existing destination differs; refusing overwrite")
        return proof
    destination.mkdir(parents=True)
    for name, blob in files.items():
        target = destination.joinpath(*PurePosixPath(name).parts)
        if not target.resolve().is_relative_to(destination.resolve()):
            raise ValueError("extraction path escaped destination")
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(blob)
    validate_directory(destination)
    return proof


def package_for_split(directory):
    root = Path(directory).parent
    if not any(
        (root / n).exists()
        for n in ("PACKAGE_MANIFEST.json", "SHA256SUMS.txt", "package_review.json")
    ):
        return None
    return validate_directory(root)


def historical_digest(proof, relative):
    """Resolve a declared source digest only after whole-package byte checks."""
    return proof["entries"][relative]["source_sha256"]


def validate_holdout_history(root, proof, raw):
    """Bind historical claims to declarations, never to substituted input bytes."""
    from scripts.plot_holdout_aggregates import OPTIONAL_RAW, REQUIRED, compare_causes
    from scripts.verify_holdout_raw import canonical, compare_summary

    root = Path(root)
    record = json_object((root / "run_record_holdout.json").read_bytes())
    data = json_object((root / "holdout_results.json").read_bytes())
    required_totals = {
        "summary_csv",
        "summary_json",
        "causes_csv",
        "causes_json",
        "guard_metadata",
    }
    if (
        not required_totals <= raw["mismatch_totals"].keys()
        or any(raw.get("mismatches", {}).values())
        or raw["source_archive_sha256"] != proof["original_archive_sha256"]
    ):
        raise ValueError("historical verification metadata inconsistent")
    for name in REQUIRED + OPTIONAL_RAW:
        if f"holdout/{name}" in proof["entries"]:
            expected = historical_digest(proof, f"holdout/{name}")
        else:
            expected = record["output_sha256"][name]
        if raw["input_sha256"].get(name) != expected:
            raise ValueError(f"historical source relation mismatch: {name}")
    for name, field in (
        ("default", "sweep_default"),
        ("tool_policy", "sweep_with_tool_policy"),
    ):
        if compare_summary(
            canonical(raw["sweeps"][name]["cells"]), canonical(data[field])
        ):
            raise ValueError("historical cells differ from reviewed aggregates")
    compare_causes(data["c_block_cause"], raw["c_causes"], data["sweep_default"])
    metadata = json_object((root / "figures/aggregate_validation.json").read_bytes())
    if (
        metadata["original_raw_verification_report_sha256"]
        != historical_digest(proof, "holdout/raw_verification.json")
        or metadata["source_archive_sha256"] != proof["original_archive_sha256"]
        or metadata["input_sha256"] != raw["input_sha256"]
    ):
        raise ValueError("historical figure report relation mismatch")
