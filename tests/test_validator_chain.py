from halcyon import audit, progress
from halcyon.store import InMemoryStore
from halcyon.validators import chain


def _emit(store, etype, details=None):
    audit.record(store, "p1", "chain", etype, "p1", details or {})


def _full(store, to_account="9931"):
    _emit(store, audit.INGEST_KEY_ACCEPTED)
    _emit(store, audit.POLICY_DOC_INGESTED, {"chunk": "c1"})
    _emit(store, audit.POISONED_DOC_RETRIEVED, {"chunk": "c1"})
    _emit(store, audit.TREASURY_TRANSFER_EXECUTED,
          {"to_account": to_account, "amount": 45000})


def test_transfer_to_the_assigned_account_passes():
    store = InMemoryStore()
    _full(store)
    r = chain.validate(store, "p1", "9931")
    assert r["core"] == "pass"
    assert all(r["stages"].values())


def test_transfer_to_any_other_account_fails():
    store = InMemoryStore()
    _full(store, to_account="1234")
    assert chain.validate(store, "p1", "9931")["core"] == "fail"


def test_stages_are_withheld_on_a_failing_validate():
    # A failing /validate/chain response is the one thing every participant
    # is certain to see in the Network tab (the CHAIN panel's own Validate
    # button hits it directly). If "stages" shipped unconditionally it would
    # hand over the whole four-step route map -- including that "retrieved"
    # is a distinct, competitive step -- before anyone has done anything.
    # Only a genuine pass earns the breakdown.
    store = InMemoryStore()
    _emit(store, audit.INGEST_KEY_ACCEPTED)
    _emit(store, audit.POLICY_DOC_INGESTED, {"chunk": "c1"})
    r = chain.validate(store, "p1", "9931")
    assert r["core"] == "fail"
    assert "stages" not in r


def test_stages_are_present_on_a_passing_validate():
    store = InMemoryStore()
    _full(store)
    r = chain.validate(store, "p1", "9931")
    assert r["core"] == "pass"
    assert r["stages"] == {"key": True, "ingested": True,
                           "retrieved": True, "transferred": True}


def test_out_of_order_events_still_pass():
    # deliberate: no strict ordering. S10's ordering check created two ways to
    # permanently brick a legitimate run, and code-level coupling already
    # prevents genuine out-of-order progress.
    store = InMemoryStore()
    _emit(store, audit.TREASURY_TRANSFER_EXECUTED,
          {"to_account": "9931", "amount": 1})
    _emit(store, audit.INGEST_KEY_ACCEPTED)
    assert chain.validate(store, "p1", "9931")["core"] == "pass"


def test_progress_is_marked():
    store = InMemoryStore()
    _full(store)
    chain.validate(store, "p1", "9931")
    assert progress.read(store, "p1", "chain") == (True, False)


def test_pass_is_durable_against_a_rotated_account():
    store = InMemoryStore()
    _full(store)
    assert chain.validate(store, "p1", "9931")["core"] == "pass"
    # a redeploy rotates the assigned account; the earned pass must survive
    assert chain.validate(store, "p1", "0000")["core"] == "pass"
    assert progress.read(store, "p1", "chain") == (True, False)


def test_reset_retracts_the_pass():
    store = InMemoryStore()
    _full(store)
    chain.validate(store, "p1", "9931")
    store.write_reset_marker("p1", "chain")
    assert chain.validate(store, "p1", "9931")["core"] == "fail"
    assert progress.read(store, "p1", "chain") == (False, False)


def test_reset_then_failed_replay_does_not_restore_the_pass():
    store = InMemoryStore()
    _full(store)
    chain.validate(store, "p1", "9931")
    store.write_reset_marker("p1", "chain")
    _full(store, to_account="1234")
    assert chain.validate(store, "p1", "9931")["core"] == "fail"
    assert progress.read(store, "p1", "chain") == (False, False)


def _marker_events(store):
    return [
        e for e in store.events_since_reset("p1", "chain")
        if e.event_type == audit.CHAIN_CORE_PASSED
    ]


def test_no_marker_is_written_on_a_failing_validate():
    # Guards the `if core and not marker_present` branch from the other
    # side: a failing validate must never leave a CHAIN_CORE_PASSED row
    # behind. A stray marker on a fail path would be a silent, permanent
    # false pass on both /validate and the class board.
    store = InMemoryStore()
    _full(store, to_account="1234")
    chain.validate(store, "p1", "9931")
    assert _marker_events(store) == []


def test_marker_is_written_at_most_once_across_repeated_passing_validates():
    # Guards the write-once half of the same branch: re-validating an
    # already-passed session must not append a second CHAIN_CORE_PASSED row.
    store = InMemoryStore()
    _full(store)
    chain.validate(store, "p1", "9931")
    chain.validate(store, "p1", "9931")
    chain.validate(store, "p1", "9931")
    assert len(_marker_events(store)) == 1


def test_marker_records_the_account_that_earned_it():
    # The durable marker is evidence, not just a flag: at a live conference a
    # disputed grade or an instructor auditing the board needs something to
    # point at, so the row that grants the pass must name the account.
    store = InMemoryStore()
    _full(store)
    chain.validate(store, "p1", "9931")
    [marker] = _marker_events(store)
    assert marker.details == {"to_account": "9931"}
