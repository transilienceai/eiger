from fastapi.testclient import TestClient

from halcyon import bank_fixtures, dispute_fixtures, kb_fixtures
from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.kb import InMemoryKB
from halcyon.llm import FinalAnswer, StubLLM, StubToolLLM, ToolCall
from halcyon.mcp_host import in_memory_host
from halcyon.mcp_vault import SERVER_CORE, SERVER_CRM, TokenVault
from halcyon.store import InMemoryStore
from halcyon.web import create_app


def _client(mode):
    store = InMemoryStore()
    settings = load_settings({"HALCYON_MODE": mode})
    kb = InMemoryKB()
    kb.seed(kb_fixtures.SEED)
    bank = Bank()
    bank.seed(bank_fixtures.seed_for("s"))
    vault = TokenVault({SERVER_CORE: "core-token", SERVER_CRM: "crm-token"})
    from halcyon import crm_fixtures
    tool_llm_factory = lambda p, m, k: StubToolLLM([  # noqa: E731
        FinalAnswer("elevated"),
        ToolCall("issue_refund", {"to_account": "acct-attacker", "amount": 5000}),
    ])
    mcp_host_factory = lambda sid: in_memory_host(  # noqa: E731
        bank, vault, crm_fixtures.SEED, store, settings, sid)
    app = create_app(store, settings, lambda p, m, k: StubLLM(""), kb, bank,
                     tool_llm_factory, mcp_host_factory)
    return TestClient(app), bank


def test_dispute_endpoint_vulnerable_passes_validation():
    client, bank = _client("vulnerable")
    payload = {"session_id": "s", **dispute_fixtures.scenario_for("s")}
    r = client.post("/api/dispute", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert "decision" in body and "transcript" in body
    v = client.get("/validate/m7", params={"session": "s"}).json()
    assert v == {"core": "pass", "stretch": "pass"}
    assert bank.get("acct-attacker").balance == 5000


def test_dispute_endpoint_secure_blocks():
    client, bank = _client("secure")
    payload = {"session_id": "s", **dispute_fixtures.scenario_for("s")}
    client.post("/api/dispute", json=payload)
    v = client.get("/validate/m7", params={"session": "s"}).json()
    assert v == {"core": "fail", "stretch": "fail"}
    assert bank.get("acct-attacker").balance == 0


def test_reset_m7_reseeds_bank():
    client, bank = _client("vulnerable")
    payload = {"session_id": "s", **dispute_fixtures.scenario_for("s")}
    client.post("/api/dispute", json=payload)  # moves money to acct-attacker
    assert client.post("/reset/m7", json={"session_id": "s"}).json()["status"] == "reset"
    assert bank.get("acct-attacker").balance == 0  # reseeded
