"""Per-session, in-process state for the S10 kill-chain capstone.

Holds the per-session CI token (S1 leak / S2 auth), the vault master secret
(the crown jewel proven exfiltrated in S5), and the mutable loot each stage
hands the next (registered artifact URL, trusted-source write). Progress + audit
persist in the external store; this is re-seedable fixture state, like Bank/KB.
"""
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field


def secret_gen() -> str:
    return secrets.token_hex(16)


@dataclass
class ChainSession:
    ci_token: str
    vault_master: str
    artifact_url: str = ""
    trusted_write: str = ""
    trusted_write_signed: bool = False


@dataclass
class ChainProvider:
    gen: Callable[[], str] = secret_gen
    _sessions: dict[str, ChainSession] = field(default_factory=dict)

    def __call__(self, session_id: str) -> ChainSession:
        s = self._sessions.get(session_id)
        if s is None:
            s = self._fresh()
            self._sessions[session_id] = s
        return s

    def reset(self, session_id: str) -> ChainSession:
        s = self._fresh()
        self._sessions[session_id] = s
        return s

    def _fresh(self) -> ChainSession:
        return ChainSession(ci_token=self.gen(), vault_master=self.gen())
