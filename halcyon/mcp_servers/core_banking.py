import mcp.types as t
from mcp.server.lowlevel import Server

from halcyon.bank import Bank
from halcyon.mcp_vault import TokenVault

_ACCOUNT = {"type": "object", "properties": {"account": {"type": "string"}},
            "required": ["account"]}
_MOVE = {"type": "object", "properties": {"to_account": {"type": "string"},
         "amount": {"type": "integer"}}, "required": ["to_account", "amount"]}
_EMAIL = {"type": "object", "properties": {"account": {"type": "string"},
          "email": {"type": "string"}}, "required": ["account", "email"]}


def build_core_banking_server(bank: Bank, vault: TokenVault) -> Server:
    srv: Server = Server("mcp-core-banking")

    @srv.list_tools()
    async def _list() -> list[t.Tool]:
        return [
            t.Tool(name="get_balance", description="Get an account balance.", inputSchema=_ACCOUNT),
            t.Tool(name="get_account_details",
                   description="Look up an account's full details including email.",
                   inputSchema=_ACCOUNT),
            t.Tool(name="transfer_funds", description="Transfer money to an account.",
                   inputSchema=_MOVE),
            t.Tool(name="issue_refund", description="Issue a refund to an account.",
                   inputSchema=_MOVE),
            t.Tool(name="update_email", description="Update an account's email.",
                   inputSchema=_EMAIL),
        ]

    @srv.call_tool()
    async def _call(name: str, args: dict) -> list[t.TextContent]:
        def text(s: str) -> list[t.TextContent]:
            return [t.TextContent(type="text", text=s)]
        if name in ("get_balance", "get_account_details"):
            a = bank.get(str(args.get("account", "")))
            if a is None:
                return text("no such account")
            if name == "get_balance":
                return text(f"balance: {a.balance}")
            return text(f"account {a.id}: email={a.email} balance={a.balance}")
        if name in ("transfer_funds", "issue_refund"):
            to = str(args.get("to_account", ""))
            try:
                amount = int(args.get("amount", 0) or 0)
            except (TypeError, ValueError):
                return text(f"{name}: invalid amount")
            if bank.get(to) is not None:
                bank.credit(to, amount)
            return text(f"{name}: moved {amount} to {to}")
        if name == "update_email":
            acct = str(args.get("account", ""))
            if bank.get(acct) is not None:
                bank.set_email(acct, str(args.get("email", "")))
            return text(f"update_email: {acct}")
        return text(f"unknown tool: {name}")

    return srv
