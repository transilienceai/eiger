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
    # Drawn from a band that starts with a leading 9, deliberately disjoint
    # from every scenario's legit_account (the 4-thousands block in
    # treasury_corpus.py). This module stays dependency-free -- it never
    # imports the corpus to check that at runtime -- so the disjointness is
    # enforced instead by a test that reads both ranges directly
    # (tests/test_treasury_state.py::test_attacker_account_band_is_disjoint_from_every_legit_account).
    # Before this fix the two ranges overlapped: a session whose assigned
    # account collided with its own scenario's legit_account could be graded
    # "passed" by a participant who did nothing but release the pending
    # payment through the front door.
    return f"{secrets.randbelow(1000) + 9000}"


@dataclass
class TreasurySession:
    ingest_key: str
    attacker_account: str
    scenario: str


@dataclass
class TreasuryProvider:
    """Provides per-session treasury state: ingest key, attacker account, scenario.

    Scenarios are assigned in round-robin order from the list. The rotation counter
    (_next) is provider-level and shared across all sessions: reset() always advances
    it, and __call__ advances it only on first access (cache miss). Uneven reset
    patterns (e.g., one participant resetting repeatedly) shift scenario assignment
    for later participants.
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
