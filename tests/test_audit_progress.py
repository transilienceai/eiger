from halcyon import audit, progress
from halcyon.store import InMemoryStore


def test_record_then_has_event():
    s = InMemoryStore()
    assert audit.has_event(s, "p1", "m1", audit.INTERNAL_TOKEN_DISCLOSED) is False
    audit.record(s, "p1", "m1", audit.INTERNAL_TOKEN_DISCLOSED, "p1")
    assert audit.has_event(s, "p1", "m1", audit.INTERNAL_TOKEN_DISCLOSED) is True


def test_has_event_respects_reset():
    s = InMemoryStore()
    audit.record(s, "p1", "m1", audit.INTERNAL_TOKEN_DISCLOSED, "p1")
    s.write_reset_marker("p1", "m1")
    assert audit.has_event(s, "p1", "m1", audit.INTERNAL_TOKEN_DISCLOSED) is False


def test_progress_roundtrip():
    s = InMemoryStore()
    assert progress.read(s, "p1", "m1") == (False, False)
    progress.mark(s, "p1", "m1", True, True)
    assert progress.read(s, "p1", "m1") == (True, True)


def test_chain_event_constants_are_distinct():
    from halcyon import audit
    chain = [
        audit.SECRET_LEAK_DISCOVERED,
        audit.MISCONFIG_EXPLOITED,
        audit.TRUSTED_INJECTION_FIRED,
        audit.MALICIOUS_ARTIFACT_LOADED,
        audit.RCE_CONFIRMED,
    ]
    assert chain == [
        "secret_leak_discovered", "misconfig_exploited", "trusted_injection_fired",
        "malicious_artifact_loaded", "rce_confirmed",
    ]
    assert len(set(chain)) == 5
