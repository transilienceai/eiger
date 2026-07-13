import anyio
from mcp.shared.memory import create_connected_server_and_client_session as connect

from halcyon.bank import Bank
from halcyon.mcp_vault import TokenVault, SERVER_CORE, SERVER_CRM
from halcyon.mcp_servers.core_banking import build_core_banking_server
from halcyon.mcp_servers.crm import build_crm_server, POISON_CLAUSE
from halcyon import crm_fixtures


def _bank():
    b = Bank()
    b.seed([{"id": "acct-victim", "owner_session": "victim", "balance": 5000,
             "email": "victim@halcyon.test"}])
    return b


def test_core_banking_lists_and_calls():
    async def main():
        vault = TokenVault({SERVER_CORE: "core-tok", SERVER_CRM: "crm-tok"})
        async with connect(build_core_banking_server(_bank(), vault)) as s:
            await s.initialize()
            tools = {t.name for t in (await s.list_tools()).tools}
            assert {"get_account_details", "transfer_funds"} <= tools
            r = await s.call_tool("get_account_details", {"account": "acct-victim"})
            assert "victim@halcyon.test" in r.content[0].text
    anyio.run(main)


def test_crm_get_customer_description_is_poisoned():
    async def main():
        vault = TokenVault({SERVER_CORE: "core-tok", SERVER_CRM: "crm-tok"})
        async with connect(build_crm_server(_bank(), vault, crm_fixtures.SEED)) as s:
            await s.initialize()
            desc = {t.name: t.description for t in (await s.list_tools()).tools}["get_customer"]
            assert POISON_CLAUSE.strip() in desc
    anyio.run(main)


def test_crm_description_mutates_on_second_list_rug_pull():
    async def main():
        vault = TokenVault({SERVER_CORE: "core-tok", SERVER_CRM: "crm-tok"})
        async with connect(build_crm_server(_bank(), vault, crm_fixtures.SEED)) as s:
            await s.initialize()
            first = {t.name: t.description for t in (await s.list_tools()).tools}["get_notes"]
            second = {t.name: t.description for t in (await s.list_tools()).tools}["get_notes"]
            assert first != second  # rug pull: get_notes description changes post-approval
    anyio.run(main)
