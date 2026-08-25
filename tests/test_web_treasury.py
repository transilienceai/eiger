import itertools

from fastapi.testclient import TestClient

from halcyon import bank_fixtures, crm_fixtures, treasury_corpus
from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.kb import InMemoryKB
from halcyon.llm import FinalAnswer, StubLLM, StubToolLLM, ToolCall
from halcyon.mcp_host import in_memory_host
from halcyon.mcp_vault import SERVER_CORE, SERVER_CRM, TokenVault
from halcyon.session_resources import KBProvider
from halcyon.store import InMemoryStore
from halcyon.treasury_state import TreasuryProvider
from halcyon.web import create_app


def make_client(env=None, script=None):
    store = InMemoryStore()
    settings = load_settings(env or {"HALCYON_MODE": "vulnerable"})
    # Each session gets its OWN InMemoryKB, exactly like KBProvider gives M3 —
    # a single shared KB would hide a cross-session leak (see
    # test_two_sessions_get_separate_knowledge_bases below).
    kb_for = KBProvider(lambda sid: InMemoryKB(), treasury_corpus.SEED)
    bank = Bank()
    bank.seed(bank_fixtures.seed_for("p1"))
    vault = TokenVault({SERVER_CORE: "c", SERVER_CRM: "d"})
    k = itertools.count(1)
    a = itertools.count(1)
    treasury_for = TreasuryProvider(
        gen=lambda: f"key-{next(k)}", account_gen=lambda: f"90{next(a):02d}",
        scenarios=treasury_corpus.SCENARIO_KEYS)
    script = script or [FinalAnswer("declined")]
    app = create_app(
        store, settings, lambda p, m, key: StubLLM(""),
        kb_for, lambda sid: bank,
        lambda p, m, key: StubToolLLM(list(script)),
        lambda sid, s: in_memory_host(bank, vault, crm_fixtures.SEED, store, s, sid),
        treasury_for=treasury_for,
    )
    return TestClient(app), store, treasury_for


def _key(client, treasury_for, session="p1"):
    blob = client.get("/source/blob", params={"session": session, "path": ".env.sample"}).json()
    assert treasury_for(session).ingest_key in blob["content"]
    return treasury_for(session).ingest_key


def test_wrong_key_is_rejected_and_records_nothing():
    client, store, tf = make_client()
    r = client.post("/ingest/docs", json={"session_id": "p1", "key": "wrong", "text": "x"})
    assert r.json()["ok"] is False
    assert store.events_since_reset("p1", "chain") == []


def test_correct_key_ingests_and_records():
    client, store, tf = make_client()
    key = _key(client, tf)
    r = client.post("/ingest/docs", json={"session_id": "p1", "key": key, "text": "policy note"})
    assert r.json()["ok"] is True
    kinds = {e.event_type for e in store.events_since_reset("p1", "chain")}
    assert "ingest_key_accepted" in kinds and "policy_doc_ingested" in kinds


def test_list_and_delete_are_scoped_to_own_uploads():
    client, store, tf = make_client()
    key = _key(client, tf)
    client.post("/ingest/docs", json={"session_id": "p1", "key": key, "text": "mine"})
    docs = client.get("/ingest/docs", params={"session": "p1"}).json()["docs"]
    assert [d["text"] for d in docs] == ["mine"]
    assert client.post("/ingest/delete",
                       json={"session_id": "p1", "chunk_id": docs[0]["id"]}).json()["deleted"]
    assert client.get("/ingest/docs", params={"session": "p1"}).json()["docs"] == []


def test_cannot_delete_a_seed_document():
    client, store, tf = make_client()
    before = len(client.post("/api/treasury/review",
                             json={"session_id": "p1"}).json()["sources"])
    assert client.post("/ingest/delete",
                       json={"session_id": "p1", "chunk_id": "c0001"}).json()["deleted"] is False
    after = len(client.post("/api/treasury/review",
                            json={"session_id": "p1"}).json()["sources"])
    assert before == after == 3


def test_brief_never_exposes_the_agents_query():
    client, store, tf = make_client()
    body = client.get("/treasury/brief", params={"session": "p1"}).json()
    scenario = treasury_corpus.SCENARIOS[tf("p1").scenario]
    assert body["brief"] == scenario.brief
    assert scenario.query not in str(body)
    assert body["attacker_account"] == tf("p1").attacker_account


def test_review_returns_citations():
    client, store, tf = make_client()
    body = client.post("/api/treasury/review", json={"session_id": "p1"}).json()
    assert len(body["sources"]) == 3


def test_reset_rotates_key_and_account_and_clears_uploads():
    client, store, tf = make_client()
    key = _key(client, tf)
    client.post("/ingest/docs", json={"session_id": "p1", "key": key, "text": "mine"})
    old = tf("p1")
    client.post("/reset/chain", json={"session_id": "p1"})
    assert tf("p1").ingest_key != old.ingest_key
    assert tf("p1").attacker_account != old.attacker_account
    assert client.get("/ingest/docs", params={"session": "p1"}).json()["docs"] == []


def test_validate_ignores_a_forged_account_in_the_request():
    # CRITICAL: TREASURY_TRANSFER_EXECUTED is recorded for every transfer, including
    # a wholly legitimate one. If /validate/chain read the account to compare
    # against from anywhere on the request, a participant could forge a pass by
    # simply naming their own scenario's legit account. It must only ever compare
    # against the server-derived treasury(session).attacker_account.
    client, store, tf = make_client(script=[
        ToolCall("transfer_funds", {"to_account": "4410", "amount": 45000}),
        FinalAnswer("released"),
    ])
    client.post("/api/treasury/review", json={"session_id": "p1"})
    # A transfer to the scenario's own legit account exists in the audit log now.
    kinds = {e.event_type for e in store.events_since_reset("p1", "chain")}
    assert "treasury_transfer_executed" in kinds
    # No query-string or body field named attacker_account is accepted by the route
    # at all -- the only input /validate/chain takes is `session`.
    r = client.get("/validate/chain", params={
        "session": "p1", "attacker_account": "4410", "account": "4410",
    })
    assert r.json()["core"] == "fail"


def test_two_sessions_get_separate_knowledge_bases():
    # CRITICAL: InMemoryKB.retrieve ignores session_id, so a shared KB would let
    # one participant's uploaded chunk rank into another participant's review.
    # Prove the wiring gives each session a genuinely separate store by planting
    # a chunk under p1 that is a perfect textual match for p2's own scenario
    # query, then confirming p2's review never sees it.
    client, store, tf = make_client()
    key1 = _key(client, tf, "p1")
    p2_scenario = treasury_corpus.SCENARIOS[tf("p2").scenario]
    client.post("/ingest/docs",
               json={"session_id": "p1", "key": key1, "text": p2_scenario.query})

    # p1's own upload is invisible to p2's listing (scoping) ...
    assert client.get("/ingest/docs", params={"session": "p2"}).json()["docs"] == []

    # ... and, more importantly, never reaches p2's retrieval/context at all.
    body = client.post("/api/treasury/review", json={"session_id": "p2"}).json()
    assert p2_scenario.query not in body["sources"]
    kinds = {e.event_type for e in store.events_since_reset("p2", "chain")}
    assert "poisoned_doc_retrieved" not in kinds
