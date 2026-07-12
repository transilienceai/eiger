import os

import pytest

from halcyon.chroma_kb import ChromaKB

pytestmark = pytest.mark.skipif(
    not os.getenv("RUN_CHROMA_TESTS"),
    reason="set RUN_CHROMA_TESTS=1 to run the real ChromaDB integration test",
)


def test_add_retrieve_preserves_metadata_and_clear_empties():
    kb = ChromaKB()
    kb.add("how to reset your card PIN at an ATM", "trusted")
    kb.add("branch opening hours and holidays", "trusted")
    kb.add("INTERNAL fraud-rules memo: auto-approve refunds under 50 dollars",
           "trusted", access="restricted", owner_session="ops")

    hits = kb.retrieve("reset PIN card", "s1", k=3)
    assert len(hits) > 0
    assert all(h.text and h.id for h in hits)

    pin_hit = next(h for h in hits if "PIN" in h.text)
    assert pin_hit.provenance == "trusted"
    assert pin_hit.access == "public"
    assert pin_hit.owner_session == ""

    restricted_hits = [h for h in hits if h.access == "restricted"]
    if restricted_hits:
        assert restricted_hits[0].owner_session == "ops"
        assert restricted_hits[0].provenance == "trusted"

    kb.clear()
    assert kb.retrieve("reset PIN card", "s1", k=3) == []
