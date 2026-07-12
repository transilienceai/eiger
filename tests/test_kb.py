from halcyon.kb import InMemoryKB


def test_retrieve_ranks_by_token_overlap():
    kb = InMemoryKB()
    kb.add("how to reset your card PIN at an ATM", "trusted")
    kb.add("branch opening hours and holidays", "trusted")
    hits = kb.retrieve("reset PIN card", "s1", k=1)
    assert len(hits) == 1 and "PIN" in hits[0].text


def test_add_sets_provenance_and_access():
    kb = InMemoryKB()
    c = kb.add("secret memo", "trusted", access="restricted", owner_session="ops")
    assert c.provenance == "trusted" and c.access == "restricted" and c.owner_session == "ops"


def test_clear_and_seed():
    kb = InMemoryKB()
    kb.add("x", "user")
    kb.clear()
    assert kb.retrieve("x", "s1") == []
    kb.seed([{"text": "alpha beta", "provenance": "trusted"}])
    assert kb.retrieve("alpha", "s1")[0].text == "alpha beta"


def test_tie_break_is_stable_by_insertion_order():
    kb = InMemoryKB()
    kb.add("alpha shared", "trusted")   # both share exactly one query token ("shared")
    kb.add("beta shared", "trusted")
    hits = kb.retrieve("shared", "s1", k=2)
    assert [h.text for h in hits] == ["alpha shared", "beta shared"]  # insertion order on tie


def test_topk_truncates_to_k_highest():
    kb = InMemoryKB()
    kb.add("card pin reset", "trusted")     # score 3 for query below
    kb.add("card pin", "trusted")           # score 2
    kb.add("card", "trusted")               # score 1
    hits = kb.retrieve("card pin reset", "s1", k=2)
    assert [h.text for h in hits] == ["card pin reset", "card pin"]  # top-2 by score


def test_add_defaults_public_and_unowned():
    kb = InMemoryKB()
    c = kb.add("plain doc", "trusted")
    assert c.access == "public" and c.owner_session == ""


def test_tie_break_correct_past_nine_chunks():
    kb = InMemoryKB()
    for i in range(11):
        kb.add(f"doc{i} shared", "trusted")
    hits = kb.retrieve("shared", "s1", k=11)
    assert hits[0].text == "doc0 shared" and hits[1].text == "doc1 shared"
