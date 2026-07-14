SERVER_CORE = "core_banking"
SERVER_CRM = "crm"


class TokenVault:
    """Models per-server MCP token storage. Cross-server scoping is enforced
    host-side (SEC_MCP_TOKEN_SCOPING in MCPHost.call); the vault only stores
    tokens and hands each server its own."""

    def __init__(self, tokens: dict[str, str]) -> None:
        self._tokens = dict(tokens)

    def own_token(self, server: str) -> str:
        return self._tokens.get(server, "")
