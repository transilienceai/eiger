import pickle
from pathlib import Path

import pytest

from halcyon import artifacts
from halcyon.config import load_settings


def _benign_pickle(tmp_path) -> Path:
    p = tmp_path / "model.pkl"
    p.write_bytes(pickle.dumps({"weights": [1, 2, 3]}))
    return p


def test_vulnerable_loads_pickle(tmp_path):
    s = load_settings({"HALCYON_MODE": "vulnerable"})
    obj = artifacts.load_artifact(_benign_pickle(tmp_path), s)
    assert obj == {"weights": [1, 2, 3]}


def test_secure_rejects_non_safetensors(tmp_path):
    s = load_settings({"HALCYON_MODE": "secure"})
    with pytest.raises(artifacts.ArtifactError):
        artifacts.load_artifact(_benign_pickle(tmp_path), s)


def test_secure_rejects_unpinned_safetensors(tmp_path):
    s = load_settings({"HALCYON_MODE": "secure"})
    f = tmp_path / "x.safetensors"
    f.write_bytes(b"not-in-allowlist")
    with pytest.raises(artifacts.ArtifactError):
        artifacts.load_artifact(f, s)


def test_secure_accepts_pinned_safetensors(tmp_path, monkeypatch):
    s = load_settings({"HALCYON_MODE": "secure"})
    f = tmp_path / "ok.safetensors"
    f.write_bytes(b"trusted-bytes")
    monkeypatch.setattr(artifacts, "ALLOWED_HASHES", {artifacts.sha256_file(f)})
    assert artifacts.load_artifact(f, s) == b"trusted-bytes"
