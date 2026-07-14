from halcyon import audit
from halcyon.store import InMemoryStore
from halcyon.validators import m6


def test_core_and_stretch_from_events():
    store = InMemoryStore()
    assert m6.validate(store, "s") == {"core": "fail", "stretch": "fail"}
    audit.record(store, "s", "m6", audit.MCP_POISONED_INVOCATION, "s")
    audit.record(store, "s", "m6", audit.TOKEN_READ, "s")
    assert m6.validate(store, "s") == {"core": "pass", "stretch": "pass"}


def test_stretch_also_passes_on_rug_pull():
    store = InMemoryStore()
    audit.record(store, "s", "m6", audit.MCP_DESC_MUTATION_ACCEPTED, "s")
    assert m6.validate(store, "s")["stretch"] == "pass"
