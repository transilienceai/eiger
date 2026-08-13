from halcyon.chain_deploy import handle_deploy
from halcyon.chain_state import ChainSession
from halcyon.config import load_settings

VULN = load_settings({"HALCYON_MODE": "vulnerable"})
SEC = load_settings({"HALCYON_MODE": "secure"})


def _sess():
    return ChainSession(ci_token="good-token", vault_master="vault-xyz")


def test_wrong_token_is_rejected_and_mutates_nothing():
    s = _sess()
    r = handle_deploy(s, "wrong", "http://x/evil.pkl", VULN)
    assert r.ok is False
    assert s.artifact_url == "" and s.trusted_write == ""


def test_vulnerable_overscope_registers_url_and_trusted_write():
    s = _sess()
    r = handle_deploy(s, "good-token", "http://x/evil.pkl", VULN)
    assert r.ok is True and r.artifact_url == "http://x/evil.pkl"
    assert s.artifact_url == "http://x/evil.pkl"
    assert "http://x/evil.pkl" in s.trusted_write
    assert s.trusted_write_signed is False


def test_least_priv_denies_even_with_valid_token():
    s = _sess()
    r = handle_deploy(s, "good-token", "http://x/evil.pkl", SEC)
    assert r.ok is False
    assert s.artifact_url == "" and s.trusted_write == ""
