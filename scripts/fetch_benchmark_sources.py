"""Download only selected, license-verified, revision-pinned benchmark snapshots.

Raw data stays in an ignored local cache, never in the source manifest or code.
An existing file is reused only when its digest matches; it is never replaced.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen

MAX_SOURCE_BYTES = 10 * 1024 * 1024


def fetch_sources(manifest_path: Path, cache_dir: Path) -> list[Path]:
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    selected = [dataset for dataset in manifest["datasets"] if dataset.get("selection")]
    if not selected:
        raise ValueError("manifest contains no selected datasets")
    destinations = set()
    for dataset in selected:
        license_info = dataset.get("license", {})
        if license_info.get("status") != "verified" or not license_info.get("spdx"):
            raise ValueError("selected dataset license is unresolved")
        revision = dataset["revision"]
        url = urlsplit(dataset["source_url"])
        if (not re.fullmatch(r"[0-9a-f]{40}", revision)
                or url.scheme != "https" or not url.hostname
                or url.username or url.password or revision not in url.path.split("/")):
            raise ValueError("source URL must be HTTPS and pinned to an exact revision")
        source_file = dataset["source_file"]
        if (not source_file or source_file in {".", ".."}
                or any(char in source_file for char in '/\\:')
                or source_file != source_file.strip()):
            raise ValueError("source_file must be a cache basename")
        if source_file.casefold() in destinations:
            raise ValueError("duplicate source_file in manifest")
        destinations.add(source_file.casefold())
        if not re.fullmatch(r"[0-9a-f]{64}", dataset["source_sha256"]):
            raise ValueError("source_sha256 must be a SHA-256 digest")

    cache_dir = Path(cache_dir).resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)
    downloaded = []
    for dataset in selected:
        destination = cache_dir / dataset["source_file"]
        if destination.is_symlink():
            raise ValueError("cache destination must not be a symlink")
        if destination.exists():
            payload = destination.read_bytes()
        else:
            with urlopen(dataset["source_url"], timeout=60) as response:
                payload = response.read(MAX_SOURCE_BYTES + 1)
            if len(payload) > MAX_SOURCE_BYTES:
                raise ValueError("source exceeds the bounded download size")
        if hashlib.sha256(payload).hexdigest() != dataset["source_sha256"]:
            raise ValueError(f"source SHA-256 mismatch: {dataset['dataset_id']}")
        if not destination.exists():
            with destination.open("xb") as stream:
                stream.write(payload)
        downloaded.append(destination)
    return downloaded


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("benchmarks/manifest.json"))
    parser.add_argument("--cache-dir", type=Path, default=Path(".cache/benchmarks"))
    args = parser.parse_args(argv)
    for path in fetch_sources(args.manifest, args.cache_dir):
        print(f"Verified SHA-256: {path}")


if __name__ == "__main__":
    main()
