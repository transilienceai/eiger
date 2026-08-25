import logging
import os

from halcyon import bank_fixtures, crm_fixtures, kb_fixtures, treasury_corpus
from halcyon.chroma_kb import ChromaKB
from halcyon.config import load_settings
from halcyon.llm import build_llm, build_tool_llm
from halcyon.mcp_config import load_mcp_servers
from halcyon.mcp_host import http_host, in_memory_host
from halcyon.mcp_vault import SERVER_CORE, SERVER_CRM, TokenVault
from halcyon.pg_store import PostgresStore, init_schema
from halcyon.session_resources import BankProvider, KBProvider, slug, treasury_collection
from halcyon.treasury_state import TreasuryProvider
from halcyon.web import create_app

_settings = load_settings(os.environ)
init_schema(_settings.database_url)
_store = PostgresStore(_settings.database_url)
_kb_for = KBProvider(lambda sid: ChromaKB(collection=slug(sid)), kb_fixtures.SEED)
_bank_for = BankProvider(bank_fixtures.seed_for)
_vault = TokenVault({SERVER_CORE: "core-token-dev", SERVER_CRM: "crm-token-dev"})
_treasury_for = TreasuryProvider(scenarios=treasury_corpus.SCENARIO_KEYS)
_treasury_kb_for = KBProvider(lambda sid: ChromaKB(collection=treasury_collection(sid)), treasury_corpus.SEED)


def _factory(provider: str | None, model: str | None, api_key: str | None):
    return build_llm(_settings, provider, model, api_key)


def _tool_llm_factory(provider: str | None, model: str | None, api_key: str | None):
    return build_tool_llm(_settings, provider, model, api_key)


# MCP servers are declared in mcp.json (source of truth), with per-server env overrides.
_mcp_servers = load_mcp_servers(os.environ)
_core_url = _mcp_servers.get("mcp-core-banking")
_crm_url = _mcp_servers.get("mcp-crm")
# Single-process deploys (pure-local dev, a single-container cloud instance) run the same
# servers in-memory instead of reaching HTTP endpoints — set MCP_IN_PROCESS=1.
_in_process = os.environ.get("MCP_IN_PROCESS", "").lower() in {"1", "true", "on", "yes"}

if not _in_process and _core_url and _crm_url:
    logging.getLogger(__name__).info(
        "mcp_host_factory: http_host over %s / %s (mcp.json / env override)", _core_url, _crm_url
    )
    # Bind narrowed locals for closure
    core_url = _core_url
    crm_url = _crm_url

    def _mcp_host_factory(session_id: str, settings=_settings):
        return http_host(core_url, crm_url, _vault, _store, settings, session_id)
else:
    # In-memory fallback: run the same servers against this process's own fixtures.
    logging.getLogger(__name__).warning(
        "mcp_host_factory: in_memory_host (MCP_IN_PROCESS=%s, core_url=%s, crm_url=%s)",
        _in_process, _core_url, _crm_url,
    )

    def _mcp_host_factory(session_id: str, settings=_settings):
        return in_memory_host(
            _bank_for(session_id), _vault, crm_fixtures.SEED, _store, settings, session_id
        )


app = create_app(
    _store, _settings, _factory, _kb_for, _bank_for, _tool_llm_factory, _mcp_host_factory,
    treasury_for=_treasury_for,
    treasury_kb_for=_treasury_kb_for,
)
