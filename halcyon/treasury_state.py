"""Per-session, in-process state for the treasury-heist capstone.

Holds the ingest key that opens the document upload door, the account the
participant is told they control (the transfer destination the grader keys
on), and which pending-transfer scenario this session was assigned. Scenario
assignment is what stops one participant's working payload from being a
working payload for the next.

Re-seedable fixture state, like Bank and KB. Progress and audit live in the
external store.
"""
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field


def key_gen() -> str:
    return secrets.token_hex(16)


def account_gen() -> str:
    return f"{secrets.randbelow(9000) + 1000}"


@dataclass
class TreasurySession:
    ingest_key: str
    attacker_account: str
    scenario: str


@dataclass
class TreasuryProvider:
    """Provides per-session treasury state: ingest key, attacker account, scenario.

    Scenarios are assigned in round-robin order from the list. The rotation counter
    (_next) is provider-level and shared across all sessions: every call to __call__
    or reset() advances the counter for the next session, so uneven reset patterns
    (e.g., one participant exploring repeatedly) shifts scenario assignment for
    later participants.
    """

    gen: Callable[[], str] = key_gen
    account_gen: Callable[[], str] = account_gen
    scenarios: list[str] = field(default_factory=lambda: ["vendor"])
    _sessions: dict[str, TreasurySession] = field(default_factory=dict)
    _next: int = 0

    def __call__(self, session_id: str) -> TreasurySession:
        s = self._sessions.get(session_id)
        if s is None:
            s = self._fresh()
            self._sessions[session_id] = s
        return s

    def reset(self, session_id: str) -> TreasurySession:
        s = self._fresh()
        self._sessions[session_id] = s
        return s

    def _fresh(self) -> TreasurySession:
        scenario = self.scenarios[self._next % len(self.scenarios)]
        self._next += 1
        return TreasurySession(
            ingest_key=self.gen(),
            attacker_account=self.account_gen(),
            scenario=scenario,
        )
