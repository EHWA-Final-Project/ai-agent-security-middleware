"""Downloader integrity tests use synthetic bytes, never benchmark measurements."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path

import pytest


@pytest.fixture
def fetcher():
    path = Path(__file__).resolve().parents[2] / "scripts/fetch_benchmark_sources.py"
    spec = importlib.util.spec_from_file_location("benchmark_fetch_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def manifest(tmp_path):
    payload = b'[{"prompt":"synthetic unit test"}]'
    entry = {
        "dataset_id": "unit-test", "revision": "a" * 40,
        "source_url": f"https://example.com/{'a' * 40}/test.json",
        "source_file": "test.json", "source_sha256": hashlib.sha256(payload).hexdigest(),
        "license": {"status": "verified", "spdx": "MIT"}, "selection": [{"source_locator": "/0"}],
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"datasets": [entry]}), encoding="utf-8")
    return path, payload, entry


def test_fetch_verifies_hash_and_reuses_cache(fetcher, manifest, tmp_path, monkeypatch):
    path, payload, _ = manifest
    monkeypatch.setattr(fetcher, "urlopen", lambda *a, **k: io.BytesIO(payload))
    cache = tmp_path / "cache"
    assert fetcher.fetch_sources(path, cache) == [cache / "test.json"]
    monkeypatch.setattr(fetcher, "urlopen", lambda *a, **k: pytest.fail("cached source fetched again"))
    fetcher.fetch_sources(path, cache)
    (cache / "test.json").write_bytes(b"tampered")
    with pytest.raises(ValueError, match="SHA-256"):
        fetcher.fetch_sources(path, cache)
    assert (cache / "test.json").read_bytes() == b"tampered"


def test_download_digest_mismatch_writes_no_source(fetcher, manifest, tmp_path, monkeypatch):
    path, _, _ = manifest
    monkeypatch.setattr(fetcher, "urlopen", lambda *a, **k: io.BytesIO(b"wrong bytes"))
    with pytest.raises(ValueError, match="SHA-256"):
        fetcher.fetch_sources(path, tmp_path / "cache")
    assert not (tmp_path / "cache" / "test.json").exists()


@pytest.mark.parametrize("changes", [
    {"source_file": "../escape.json"}, {"source_file": "C:escape.json"},
    {"source_url": "https://example.com/main/data.json"},
    {"license": {"status": "unresolved"}}, {"revision": "main"},
])
def test_invalid_source_rejected_before_network(fetcher, manifest, tmp_path, monkeypatch, changes):
    path, _, entry = manifest
    entry.update(changes)
    path.write_text(json.dumps({"datasets": [entry]}), encoding="utf-8")
    monkeypatch.setattr(fetcher, "urlopen", lambda *a, **k: pytest.fail("unexpected download"))
    with pytest.raises(ValueError):
        fetcher.fetch_sources(path, tmp_path / "cache")
    assert not (tmp_path / "cache").exists()
