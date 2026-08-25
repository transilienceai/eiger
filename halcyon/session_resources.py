"""Per-session, in-process resource providers.

Bank and KB state is re-seedable fixture data, so it lives in the app process
keyed by session_id (progress + audit already persist in the external store).
This isolates the 22 participants from each other; it is NOT RCE isolation.
"""
import hashlib
from collections.abc import Callable

from halcyon.bank import Bank
from halcyon.kb import KnowledgeBase


def slug(session_id: str) -> str:
    """A Chroma-legal collection name (3-63 chars, [a-zA-Z0-9_-], alnum ends)."""
    return "s" + hashlib.sha1(session_id.encode()).hexdigest()[:32]


def treasury_collection(session_id: str) -> str:
    """Chroma collection for the capstone's own store, separate from M3's KB.

    The prefix goes AFTER the hash. slug("treasury-" + sid) would collide:
    hashing a concatenation destroys the boundary, so session id "treasury-p1"
    would resolve to participant p1's treasury collection via M3's
    unauthenticated routes. This scheme is safe because slug() always returns
    "s" + hex (33 chars), while "treasury_" + hex is always 42 chars starting "t",
    so length and first character both differ unconditionally.
    """
    return "treasury_" + slug(session_id)


class BankProvider:
    def __init__(self, seed_for: Callable[[str], list[dict]]) -> None:
        self._seed_for = seed_for
        self._banks: dict[str, Bank] = {}

    def __call__(self, session_id: str) -> Bank:
        bank = self._banks.get(session_id)
        if bank is None:
            bank = Bank()
            bank.seed(self._seed_for(session_id))
            self._banks[session_id] = bank
        return bank


class KBProvider:
    def __init__(self, make_kb: Callable[[str], KnowledgeBase], seed: list[dict]) -> None:
        self._make_kb = make_kb
        self._seed = seed
        self._kbs: dict[str, KnowledgeBase] = {}

    def __call__(self, session_id: str) -> KnowledgeBase:
        kb = self._kbs.get(session_id)
        if kb is None:
            kb = self._make_kb(session_id)
            kb.seed(self._seed)
            self._kbs[session_id] = kb
        return kb
