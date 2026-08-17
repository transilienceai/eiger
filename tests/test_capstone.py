from halcyon import audit, capstone
from halcyon.store import InMemoryStore
from halcyon.validators import chain as chain_validator
from halcyon.validators import m1, m2, m3, m4, m5, m6, m7, m8


def test_empty_session_nothing_exploited():
    store = InMemoryStore()
    r = capstone.residual_risk(store, "s")
    assert r["total"] == 9
    assert r["exploited_count"] == 0
    assert all(m["exploited"] is False for m in r["modules"])


def test_exploited_modules_are_reported():
    store = InMemoryStore()
    audit.record(store, "s", "m1", audit.INTERNAL_TOKEN_DISCLOSED, "s")
    audit.record(store, "s", "m8", audit.GUARDRAIL_BYPASSED, "s")
    r = capstone.residual_risk(store, "s")
    by_id = {m["module"]: m for m in r["modules"]}
    assert by_id["m1"]["exploited"] is True
    assert by_id["m8"]["exploited"] is True
    assert by_id["m5"]["exploited"] is False
    assert r["exploited_count"] == 2


def test_multi_event_core_requires_all_events():
    # m3 core needs BOTH poisoned_chunk_in_context AND rag_injection_fired
    store = InMemoryStore()
    audit.record(store, "s", "m3", audit.POISONED_CHUNK_IN_CONTEXT, "s")
    assert {m["module"]: m for m in capstone.residual_risk(store, "s")["modules"]}["m3"]["exploited"] is False
    audit.record(store, "s", "m3", audit.RAG_INJECTION_FIRED, "s")
    assert {m["module"]: m for m in capstone.residual_risk(store, "s")["modules"]}["m3"]["exploited"] is True


def _validators():
    # chain.validate has an extra required `vault_master` arg (it's not just an
    # audit-event query -- see validators/chain.py). Wrap it to the same
    # (store, session_id) -> {"core": ...} shape as every other validator; the
    # dummy secret is irrelevant here because CORE_EVENTS["chain"] tests the
    # *durable* CHAIN_CORE_PASSED marker path, which short-circuits the
    # secret/order check once the marker itself is present (see module docstring).
    return {
        "m1": m1.validate, "m2": m2.validate, "m3": m3.validate, "m4": m4.validate,
        "m5": m5.validate, "m6": m6.validate, "m7": m7.validate, "m8": m8.validate,
        "chain": lambda store, sid: chain_validator.validate(store, sid, "irrelevant-vault-master"),
    }


def test_core_events_map_stays_in_sync_with_validators():
    # Seeding exactly capstone.CORE_EVENTS[m] must flip that module's validator core to pass.
    validators = _validators()
    for module, events in capstone.CORE_EVENTS.items():
        store = InMemoryStore()
        assert validators[module](store, "s")["core"] == "fail"
        for e in events:
            audit.record(store, "s", module, e, "s")
        assert validators[module](store, "s")["core"] == "pass", module


def test_every_core_event_is_necessary():
    # For each module's CORE_EVENTS, dropping any single event must keep the
    # validator core at "fail" — proves no listed event is a superset/redundant
    # entry that would let the capstone under-report residual risk.
    validators = _validators()
    for module, events in capstone.CORE_EVENTS.items():
        for missing in events:
            store = InMemoryStore()
            for e in events:
                if e != missing:
                    audit.record(store, "s", module, e, "s")
            assert validators[module](store, "s")["core"] == "fail", (module, missing)
