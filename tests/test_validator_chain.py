from halcyon import audit, progress
from halcyon.store import InMemoryStore
from halcyon.validators import chain


def _emit(store, etype, details=None):
    audit.record(store, "p1", "chain", etype, "p1", details or {})


def _full_in_order(store, secret="VAULT"):
    _emit(store, audit.SECRET_LEAK_DISCOVERED)
    _emit(store, audit.MISCONFIG_EXPLOITED)
    _emit(store, audit.TRUSTED_INJECTION_FIRED)
    _emit(store, audit.MALICIOUS_ARTIFACT_LOADED)
    _emit(store, audit.RCE_CONFIRMED, {"secret": secret})


def test_full_chain_in_order_with_matching_secret_passes():
    store = InMemoryStore()
    _full_in_order(store, secret="VAULT")
    r = chain.validate(store, "p1", "VAULT")
    assert r["core"] == "pass"
    assert all(r["stages"].values())
    assert progress.read(store, "p1", "chain") == (True, False)


def test_missing_a_link_fails_and_stages_show_the_gap():
    store = InMemoryStore()
    _emit(store, audit.SECRET_LEAK_DISCOVERED)
    _emit(store, audit.MISCONFIG_EXPLOITED)
    r = chain.validate(store, "p1", "VAULT")
    assert r["core"] == "fail"
    assert r["stages"][audit.SECRET_LEAK_DISCOVERED] is True
    assert r["stages"][audit.RCE_CONFIRMED] is False
    assert progress.read(store, "p1", "chain") == (False, False)


def test_wrong_secret_fails_even_with_all_events():
    store = InMemoryStore()
    _full_in_order(store, secret="NOT-THE-SECRET")
    assert chain.validate(store, "p1", "VAULT")["core"] == "fail"


def test_out_of_order_events_fail():
    store = InMemoryStore()
    # rce_confirmed emitted before its prerequisites (forged / replayed)
    _emit(store, audit.RCE_CONFIRMED, {"secret": "VAULT"})
    _emit(store, audit.SECRET_LEAK_DISCOVERED)
    _emit(store, audit.MISCONFIG_EXPLOITED)
    _emit(store, audit.TRUSTED_INJECTION_FIRED)
    _emit(store, audit.MALICIOUS_ARTIFACT_LOADED)
    assert chain.validate(store, "p1", "VAULT")["core"] == "fail"


def test_reset_marker_clears_pass():
    store = InMemoryStore()
    _full_in_order(store, secret="VAULT")
    assert chain.validate(store, "p1", "VAULT")["core"] == "pass"
    store.write_reset_marker("p1", "chain")
    assert chain.validate(store, "p1", "VAULT")["core"] == "fail"
    assert progress.read(store, "p1", "chain") == (False, False)


def test_stored_pass_survives_a_later_failing_revalidate():
    # e.g. a redeploy mints a fresh vault_master; the audit log still holds
    # the old secret. A stored pass must not be erased by that stale replay.
    store = InMemoryStore()
    _full_in_order(store, secret="VAULT")
    assert chain.validate(store, "p1", "VAULT")["core"] == "pass"
    assert progress.read(store, "p1", "chain") == (True, False)

    r = chain.validate(store, "p1", "NEW-SECRET-AFTER-REDEPLOY")
    assert r["core"] == "fail"  # this call's own observation is truthful...
    assert progress.read(store, "p1", "chain") == (True, False)  # ...but the stored pass stands


def test_reset_then_failed_full_replay_clears_pass():
    # Subtler than the empty-window reset case: after a reset, a
    # participant may legitimately replay the *entire* chain again and
    # still fail (e.g. wrong secret). All five stage types recur, but the
    # pass-marker from before the reset does not survive it -- the stored
    # pass must not be treated as still valid just because the stages are
    # present again.
    store = InMemoryStore()
    _full_in_order(store, secret="VAULT")
    assert chain.validate(store, "p1", "VAULT")["core"] == "pass"
    assert progress.read(store, "p1", "chain") == (True, False)

    store.write_reset_marker("p1", "chain")
    _full_in_order(store, secret="WRONG-SECRET")  # legitimate post-reset replay, fails
    r = chain.validate(store, "p1", "VAULT")
    assert r["core"] == "fail"
    assert progress.read(store, "p1", "chain") == (False, False)


def test_re_reading_an_earlier_stage_after_finishing_does_not_lose_the_pass():
    # First-occurrence semantics: a participant who re-triggers an earlier
    # stage (e.g. re-reads the leaked secret blob) after already completing
    # the chain must still pass — only the *first* sighting of each stage
    # counts for ordering.
    store = InMemoryStore()
    _full_in_order(store, secret="VAULT")
    _emit(store, audit.SECRET_LEAK_DISCOVERED)  # re-triggered after finishing
    r = chain.validate(store, "p1", "VAULT")
    assert r["core"] == "pass"
    assert all(r["stages"].values())
    assert progress.read(store, "p1", "chain") == (True, False)
