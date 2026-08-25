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


def test_stages_show_where_they_stopped():
    store = InMemoryStore()
    _emit(store, audit.INGEST_KEY_ACCEPTED)
    _emit(store, audit.POLICY_DOC_INGESTED, {"chunk": "c1"})
    r = chain.validate(store, "p1", "9931")
    assert r["core"] == "fail"
    assert r["stages"] == {"key": True, "ingested": True,
                           "retrieved": False, "transferred": False}


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
