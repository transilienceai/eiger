from collections.abc import Callable

SERVER_CORE = "core_banking"
SERVER_CRM = "crm"


class TokenVault:
    """Models per-server MCP token storage. Vulnerable = every server can read
    any token; secure (SEC_MCP_TOKEN_SCOPING) = a server reads only its own."""

    def __init__(self, tokens: dict[str, str]) -> None:
        self._tokens = dict(tokens)
        # Isolation default: read_for_crm resolves straight through to the raw
        # token store. Task 3's host binds a scoped wrapper via bind_crm.
        self.read_for_crm: Callable[[str], str | None] = lambda service: self._tokens.get(service)

    def own_token(self, server: str) -> str:
        return self._tokens.get(server, "")
