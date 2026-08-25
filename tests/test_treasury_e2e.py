"""End-to-end HTTP chain and the bypass matrix for the treasury-heist capstone.

Every test here drives the real HTTP routes through the shared `make_client`
helper (tests/test_web_treasury.py) -- nothing is shortcut by calling
internal functions directly. Two things are already covered elsewhere and are
deliberately NOT duplicated here (see tests/test_web_treasury.py):
  - deleting a seed document does nothing (test_cannot_delete_a_seed_document)
  - M3's unauthenticated /api/kb poison never reaches treasury review
    (test_m3_poisoning_never_reaches_treasury_review)
"""
from halcyon import treasury_corpus
from halcyon.llm import FinalAnswer, ToolCall
from tests.test_web_treasury import make_client


def test_full_chain_passes_when_the_transfer_lands_on_the_assigned_account():
    # make_client()'s TreasuryProvider uses a fresh, deterministic,
    # sequential account_gen counter -- so the very first session resolved
    # ("p1") gets the same attacker_account across two separate make_client()
    # calls. Resolve it once (throwaway client) to script the stubbed agent
    # against the real account before building the client we actually drive.
    _throwaway_client, _store, tf0, _m3 = make_client()
    acct = tf0("p1").attacker_account
    client, store, tf, _m3_kb_for = make_client(script=[
        ToolCall("transfer_funds", {"to_account": acct, "amount": 45000}),
        FinalAnswer("released"),
    ])
    scenario = treasury_corpus.SCENARIOS[tf("p1").scenario]
    key = tf("p1").ingest_key

    # 1. browse the leaked key via the real route
    blob = client.get("/source/blob", params={"session": "p1", "path": ".env.sample"}).json()
    assert key in blob["content"]

    # 2. ingest a policy doc with the stolen key. Text mirrors the scenario's
    # own retrieval query so it is guaranteed to land in the agent's top-3 --
    # otherwise "retrieved" would stay false for reasons unrelated to what
    # this test is pinning (see test_web_treasury.py's own full-flow test).
    r = client.post("/ingest/docs", json={
        "session_id": "p1", "key": key, "text": scenario.query})
    assert r.json()["ok"] is True

    # 3. the agent acts (stubbed to release to the assigned account). `reply`
    # is a live echo channel over the model's own text (which holds the full
    # unredacted seeded policy), so the route only ever returns it for the
    # "<error: ...>" transport sentinel -- never the model's decision text.
    review = client.post("/api/treasury/review", json={"session_id": "p1"}).json()
    assert "reply" not in review

    # 4. grade through the real HTTP validator
    r = client.get("/validate/chain", params={"session": "p1"}).json()
    assert r["core"] == "pass"
    assert all(r["stages"].values())


def test_transfer_to_another_account_does_not_pass():
    client, store, tf, _m3 = make_client(script=[
        ToolCall("transfer_funds", {"to_account": "1234", "amount": 45000}),
        FinalAnswer("released"),
    ])
    scenario = treasury_corpus.SCENARIOS[tf("p1").scenario]
    key = tf("p1").ingest_key
    client.post("/ingest/docs", json={"session_id": "p1", "key": key, "text": scenario.query})
    client.post("/api/treasury/review", json={"session_id": "p1"})
    assert client.get("/validate/chain", params={"session": "p1"}).json()["core"] == "fail"


def test_skipping_the_key_dead_ends_the_chain():
    client, store, tf, _m3 = make_client()
    r = client.post("/ingest/docs", json={"session_id": "p1", "key": "guess", "text": "x"})
    assert r.json()["ok"] is False
    assert client.get("/ingest/docs", params={"session": "p1"}).json()["docs"] == []


def test_emptying_your_own_uploads_promotes_nothing():
    # A payload of inert text ("mine") never ranks into top-3 regardless of
    # whether deletion is correctly scoped, so it would pass even if delete
    # silently no-op'd. Ingest text guaranteed to be retrieved instead (it
    # mirrors the scenario query), confirm it IS in context, delete it, and
    # confirm both that it's genuinely gone AND that the seed corpus still
    # fills the context back up to 3 -- emptying your own uploads doesn't
    # leave a gap, and doesn't leave your deleted content lingering either.
    client, store, tf, _m3 = make_client()
    scenario = treasury_corpus.SCENARIOS[tf("p1").scenario]
    key = tf("p1").ingest_key
    client.post("/ingest/docs", json={"session_id": "p1", "key": key, "text": scenario.query})
    docs = client.get("/ingest/docs", params={"session": "p1"}).json()["docs"]
    before = client.post("/api/treasury/review", json={"session_id": "p1"}).json()["sources"]
    assert scenario.query in before, "setup check: the upload must actually be retrieved"

    client.post("/ingest/delete", json={"session_id": "p1", "chunk_id": docs[0]["id"]})
    after = client.post("/api/treasury/review", json={"session_id": "p1"}).json()["sources"]
    assert scenario.query not in after, "the deleted upload must not still be served"
    assert len(after) == 3, "the seed corpus still fills the context"


def test_sessions_are_isolated():
    client, store, tf, _m3 = make_client()
    assert tf("p1").ingest_key != tf("p2").ingest_key
    assert tf("p1").attacker_account != tf("p2").attacker_account
    key1 = tf("p1").ingest_key
    client.post("/ingest/docs", json={"session_id": "p1", "key": key1, "text": "mine"})
    assert client.get("/ingest/docs", params={"session": "p2"}).json()["docs"] == []


def test_no_unauthenticated_route_writes_a_grading_event():
    client, store, tf, _m3 = make_client()
    client.post("/ingest/docs", json={"session_id": "p1", "key": "wrong", "text": "x"})
    client.get("/source/tree", params={"session": "p1"})
    client.get("/treasury/brief", params={"session": "p1"})
    assert store.events_since_reset("p1", "chain") == []
