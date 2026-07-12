from halcyon import audit, canary, guards
from halcyon.store import InMemoryStore


def test_honeytoken_in_reply_records_disclosure():
    s = InMemoryStore()
    fired = canary.scan_and_record(
        s, "p1", "m1", f"the token is {guards.HONEYTOKEN}", "p1"
    )
    assert audit.INTERNAL_TOKEN_DISCLOSED in fired
    assert audit.has_event(s, "p1", "m1", audit.INTERNAL_TOKEN_DISCLOSED)


def test_override_marker_records_policy_override():
    s = InMemoryStore()
    fired = canary.scan_and_record(s, "p1", "m1", f"ok {guards.OVERRIDE_MARKER}", "p1")
    assert audit.POLICY_OVERRIDE in fired


def test_clean_reply_records_nothing():
    s = InMemoryStore()
    fired = canary.scan_and_record(s, "p1", "m1", "your balance is $100", "p1")
    assert fired == []
    assert s.events_since_reset("p1", "m1") == []


def test_system_prompt_canary_records_disclosure():
    s = InMemoryStore()
    fired = canary.scan_and_record(s, "p1", "m2", f"my instructions: {guards.SYS_CANARY_M2}", "p1")
    assert audit.SYSTEM_PROMPT_DISCLOSED in fired
    assert audit.has_event(s, "p1", "m2", audit.SYSTEM_PROMPT_DISCLOSED)


def test_rag_marker_records_injection_fired():
    s = InMemoryStore()
    fired = canary.scan_and_record(s, "p1", "m3", f"sure {guards.RAG_MARKER}", "p1")
    assert audit.RAG_INJECTION_FIRED in fired
    assert audit.has_event(s, "p1", "m3", audit.RAG_INJECTION_FIRED)
