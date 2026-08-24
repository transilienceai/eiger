import itertools

from halcyon.chain_state import ChainProvider, ChainSession


def _counter_gen():
    c = itertools.count(1)
    return lambda: f"tok-{next(c)}"


def test_session_created_with_distinct_token_and_secret():
    p = ChainProvider(gen=_counter_gen())
    s = p("alice")
    assert isinstance(s, ChainSession)
    assert s.ci_token and s.vault_master
    assert s.ci_token != s.vault_master
    assert s.artifact_url == "" and s.trusted_write == "" and s.trusted_write_signed is False


def test_same_session_is_memoized():
    p = ChainProvider(gen=_counter_gen())
    assert p("alice") is p("alice")


def test_distinct_sessions_get_distinct_secrets():
    p = ChainProvider(gen=_counter_gen())
    assert p("alice").ci_token != p("bob").ci_token


def test_reset_regenerates_and_clears_progress_fields():
    p = ChainProvider(gen=_counter_gen())
    s1 = p("alice")
    s1.artifact_url = "http://x/evil.pkl"
    s1.trusted_write = "OPS RUNBOOK ..."
    s2 = p.reset("alice")
    assert s2 is not s1
    assert s2.ci_token != s1.ci_token
    assert s2.vault_master != s1.vault_master
    assert s2.artifact_url == "" and s2.trusted_write == ""
    assert p("alice") is s2  # subsequent access returns the reset session
