import pytest
from fastapi.testclient import TestClient

from halcyon import crm_fixtures, kb_fixtures
from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.kb import InMemoryKB
from halcyon.llm import FinalAnswer, StubLLM, StubToolLLM
from halcyon.mcp_host import in_memory_host
from halcyon.mcp_vault import SERVER_CORE, SERVER_CRM, TokenVault
from halcyon.store import InMemoryStore
from halcyon.web import create_app


@pytest.fixture
def m6_client():
    store = InMemoryStore()
    settings = load_settings({"HALCYON_MODE": "vulnerable"})
    kb = InMemoryKB()
    kb.seed(kb_fixtures.SEED)
    bank = Bank()
    vault = TokenVault({SERVER_CORE: "core-token", SERVER_CRM: "crm-token"})
    tool_llm_factory = lambda p, m, k: StubToolLLM([FinalAnswer("ok")])  # noqa: E731
    mcp_host_factory = lambda sid: in_memory_host(  # noqa: E731
        bank, vault, crm_fixtures.SEED, store, settings, sid
    )
    app = create_app(
        store, settings, lambda provider, model, api_key: StubLLM(""), kb, bank,
        tool_llm_factory, mcp_host_factory,
    )
    return TestClient(app)


def test_mcp_agent_endpoint_and_validate(m6_client):
    r = m6_client.post("/api/mcp-agent", json={"session_id": "s", "message": "hi"})
    assert r.status_code == 200
    assert "reply" in r.json() and "tool_calls" in r.json()
    assert m6_client.get("/validate/m6", params={"session": "s"}).status_code == 200
    assert m6_client.post("/reset/m6", json={"session_id": "s"}).json()["status"] == "reset"
