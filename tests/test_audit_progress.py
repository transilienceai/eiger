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


def test_s11_capstone_event_constants_are_distinct():
    from halcyon import audit
    events = [
        audit.INGEST_KEY_ACCEPTED,
        audit.POLICY_DOC_INGESTED,
        audit.POISONED_DOC_RETRIEVED,
        audit.TREASURY_TRANSFER_EXECUTED,
        audit.CHAIN_CORE_PASSED,
    ]
    assert events == [
        "ingest_key_accepted", "policy_doc_ingested", "poisoned_doc_retrieved",
        "treasury_transfer_executed", "chain_core_passed",
    ]
    assert len(set(events)) == 5


def test_s10_stage_constants_are_gone():
    from halcyon import audit
    for name in ("SECRET_LEAK_DISCOVERED", "MISCONFIG_EXPLOITED",
                 "TRUSTED_INJECTION_FIRED", "MALICIOUS_ARTIFACT_LOADED",
                 "RCE_CONFIRMED"):
        assert not hasattr(audit, name), f"{name} should have been removed with S10"
