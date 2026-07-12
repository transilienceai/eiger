from halcyon import audit
from halcyon.store import InMemoryStore
from halcyon.validators import m3


def test_core_needs_both_signals():
    s = InMemoryStore()
    audit.record(s, "p1", "m3", audit.POISONED_CHUNK_IN_CONTEXT, "p1")
    assert m3.validate(s, "p1")["core"] == "fail"
    audit.record(s, "p1", "m3", audit.RAG_INJECTION_FIRED, "p1")
    assert m3.validate(s, "p1")["core"] == "pass"


def test_stretch_on_restricted_retrieval():
    s = InMemoryStore()
    audit.record(s, "p1", "m3", audit.RESTRICTED_DOC_RETRIEVED, "p1")
    assert m3.validate(s, "p1")["stretch"] == "pass"
