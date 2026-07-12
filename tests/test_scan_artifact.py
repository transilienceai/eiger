import os
import pickle

from halcyon import scan_artifact


class _Exploit:
    def __reduce__(self):
        return (os.system, ("echo pwned",))


def test_benign_pickle_is_clean(tmp_path):
    p = tmp_path / "benign.pkl"
    p.write_bytes(pickle.dumps({"a": 1}))
    result = scan_artifact.scan(p)
    assert result["malicious"] is False and result["dangerous"] == []


def test_malicious_pickle_flagged(tmp_path):
    p = tmp_path / "evil.pkl"
    p.write_bytes(pickle.dumps(_Exploit()))  # dumps does NOT execute; safe to create
    result = scan_artifact.scan(p)
    assert result["malicious"] is True
    assert any("os" in d or "REDUCE" in d for d in result["dangerous"])
    assert len(result["sha256"]) == 64


def test_non_pickle_file_is_clean(tmp_path):
    # A genuine .safetensors (non-pickle bytes) is NOT a malicious pickle — a genops
    # parse failure must not be treated as a dangerous finding.
    p = tmp_path / "embedding_model.safetensors"
    p.write_bytes(b"SAFE_PLACEHOLDER_TENSOR_DATA")
    result = scan_artifact.scan(p)
    assert result["malicious"] is False and result["dangerous"] == []


def test_real_fixtures_distinguish_poison_from_benign():
    poison = scan_artifact.scan("labs/m4/artifacts/community_model.pkl")
    benign = scan_artifact.scan("labs/m4/artifacts/embedding_model.safetensors")
    assert poison["malicious"] is True
    assert benign["malicious"] is False
