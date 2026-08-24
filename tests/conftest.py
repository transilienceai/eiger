import itertools

from fastapi.testclient import TestClient

from halcyon import crm_fixtures, kb_fixtures
from halcyon.bank import Bank
from halcyon.chain_state import ChainProvider
from halcyon.config import load_settings
from halcyon.kb import InMemoryKB
from halcyon.llm import StubLLM, StubToolLLM
from halcyon.mcp_host import in_memory_host
from halcyon.mcp_vault import SERVER_CORE, SERVER_CRM, TokenVault
from halcyon.store import InMemoryStore
from halcyon.web import create_app


def make_chain_client(env, ops_script):
    """Build a fully-wired, deterministic capstone TestClient.

    Shared across the chain test modules (test_web_chain.py, test_chain_e2e.py)
    so there is exactly one definition of this wiring.
    """
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
