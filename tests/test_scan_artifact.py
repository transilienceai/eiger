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
