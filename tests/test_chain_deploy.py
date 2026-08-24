from halcyon.chain_deploy import apply_deploy, handle_deploy
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


def test_vulnerable_overscope_computes_url_and_trusted_write():
    s = _sess()
    r = handle_deploy(s, "good-token", "http://x/evil.pkl", VULN)
    assert r.ok is True and r.artifact_url == "http://x/evil.pkl"
    assert "http://x/evil.pkl" in r.trusted_write
    # handle_deploy is pure -- it never mutates session. apply_deploy does, and
    # the caller (web.py) must only call apply_deploy after recording the audit
    # event, closing the deploy race (see module docstring / Fix 2).
    assert s.artifact_url == "" and s.trusted_write == ""


def test_least_priv_denies_even_with_valid_token():
    s = _sess()
    r = handle_deploy(s, "good-token", "http://x/evil.pkl", SEC)
    assert r.ok is False
    assert s.artifact_url == "" and s.trusted_write == ""


def test_apply_deploy_writes_the_computed_mutation():
    s = _sess()
    r = handle_deploy(s, "good-token", "http://x/evil.pkl", VULN)
    apply_deploy(s, r)
    assert s.artifact_url == "http://x/evil.pkl"
    assert "http://x/evil.pkl" in s.trusted_write
    assert s.trusted_write_signed is False


def test_race_window_a_concurrent_reader_sees_no_trusted_write_before_apply():
    # Regression for the deploy race (Fix 2): between handle_deploy's decision
    # and the caller applying it, a concurrent /api/ops-agent request reading
    # `session` must see an empty trusted_write -- it cannot possibly fire
    # TRUSTED_INJECTION_FIRED at that point, which is what keeps the audit
    # ordering (misconfig_exploited before trusted_injection_fired) intact no
    # matter how two requests interleave.
    s = _sess()
    r = handle_deploy(s, "good-token", "http://x/evil.pkl", VULN)
    assert r.ok is True
    assert s.trusted_write == ""  # a concurrent reader right here sees nothing to act on
    apply_deploy(s, r)
    assert s.trusted_write != ""
