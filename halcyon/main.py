import logging
import os

from halcyon import crm_fixtures, kb_fixtures
from halcyon.bank import Bank
from halcyon.chroma_kb import ChromaKB
from halcyon.config import load_settings
from halcyon.llm import build_llm, build_tool_llm
from halcyon.mcp_host import in_memory_host
from halcyon.mcp_vault import SERVER_CORE, SERVER_CRM, TokenVault
from halcyon.pg_store import PostgresStore, init_schema
from halcyon.web import create_app

_settings = load_settings(os.environ)
init_schema(_settings.database_url)
_store = PostgresStore(_settings.database_url)
_kb = ChromaKB()
_kb.seed(kb_fixtures.SEED)
_bank = Bank()
_vault = TokenVault({SERVER_CORE: "core-token-dev", SERVER_CRM: "crm-token-dev"})


def _factory(provider: str | None, model: str | None, api_key: str | None):
    return build_llm(_settings, provider, model, api_key)


def _tool_llm_factory(provider: str | None, model: str | None, api_key: str | None):
    return build_tool_llm(_settings, provider, model, api_key)


# Task 8 wires a real http_host(...) pointing at MCP_CORE_URL / MCP_CRM_URL.
# Until then, fall back to an in-memory MCP host bound to this process's own
# bank/vault/CRM fixtures for local single-process dev.
logging.getLogger(__name__).warning(
    "mcp_host_factory: using in_memory_host fallback (no MCP container transport wired yet)"
)


def _mcp_host_factory(session_id: str):
    return in_memory_host(_bank, _vault, crm_fixtures.SEED, _store, _settings, session_id)


app = create_app(_store, _settings, _factory, _kb, _bank, _tool_llm_factory, _mcp_host_factory)
