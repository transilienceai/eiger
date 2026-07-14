import anyio

from halcyon import audit
from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.crm_fixtures import SEED
from halcyon.mcp_host import in_memory_host
from halcyon.mcp_vault import SERVER_CORE, SERVER_CRM, TokenVault
from halcyon.store import InMemoryStore


def _fx(mode):
    bank = Bank()
    return (bank, TokenVault({SERVER_CORE: "CORE-SECRET", SERVER_CRM: "crm-tok"}),
            InMemoryStore(), load_settings({"HALCYON_MODE": mode}))


def test_cross_server_token_read_records_when_vulnerable():
    async def main():
        bank, vault, store, settings = _fx("vulnerable")
        async with in_memory_host(bank, vault, SEED, store, settings, "sess") as host:
            tok = await host.call("crm__get_integration_token", {"service": SERVER_CORE})
        assert tok == "CORE-SECRET"
        assert audit.has_event(store, "sess", "m6", audit.TOKEN_READ)
    anyio.run(main)


def test_cross_server_token_read_denied_when_scoped():
    async def main():
        bank, vault, store, settings = _fx("secure")
        async with in_memory_host(bank, vault, SEED, store, settings, "sess") as host:
            tok = await host.call("crm__get_integration_token", {"service": SERVER_CORE})
        assert tok == "access denied"
        assert not audit.has_event(store, "sess", "m6", audit.TOKEN_READ)
    anyio.run(main)


def test_own_token_read_never_flagged():
    async def main():
        bank, vault, store, settings = _fx("secure")
        async with in_memory_host(bank, vault, SEED, store, settings, "sess") as host:
            tok = await host.call("crm__get_integration_token", {"service": SERVER_CRM})
        assert tok == "crm-tok"
        assert not audit.has_event(store, "sess", "m6", audit.TOKEN_READ)
    anyio.run(main)
