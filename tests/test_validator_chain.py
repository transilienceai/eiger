from halcyon import audit
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


def test_missing_a_link_fails_and_stages_show_the_gap():
    store = InMemoryStore()
    _emit(store, audit.SECRET_LEAK_DISCOVERED)
    _emit(store, audit.MISCONFIG_EXPLOITED)
    r = chain.validate(store, "p1", "VAULT")
    assert r["core"] == "fail"
    assert r["stages"][audit.SECRET_LEAK_DISCOVERED] is True
    assert r["stages"][audit.RCE_CONFIRMED] is False


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
