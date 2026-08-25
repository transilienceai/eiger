from halcyon.kb import InMemoryKB


def _kb():
    kb = InMemoryKB()
    kb.seed([{"text": "Wire cut-off is 16:00 local.", "provenance": "trusted"}])
    kb.add("my first attempt", "user", owner_session="alice")
    kb.add("my second attempt", "user", owner_session="alice")
    kb.add("bob's attempt", "user", owner_session="bob")
    return kb


def test_list_own_returns_only_the_callers_uploads():
    kb = _kb()
    texts = [c.text for c in kb.list_own("alice")]
    assert texts == ["my first attempt", "my second attempt"]


def test_list_own_never_exposes_the_seed_corpus():
    kb = _kb()
    assert all(c.provenance == "user" for c in kb.list_own("alice"))
    assert not any("Wire cut-off" in c.text for c in kb.list_own("alice"))


def test_delete_own_removes_only_that_chunk():
    kb = _kb()
    target = kb.list_own("alice")[0]
    assert kb.delete_own("alice", target.id) is True
    assert [c.text for c in kb.list_own("alice")] == ["my second attempt"]


def test_cannot_delete_another_sessions_upload():
    kb = _kb()
    bob_chunk = kb.list_own("bob")[0]
    assert kb.delete_own("alice", bob_chunk.id) is False
    assert len(kb.list_own("bob")) == 1


def test_cannot_delete_a_seed_document():
    kb = _kb()
    # the seeded chunk is c0001 — deleting it would empty the field the
    # participant is supposed to compete against
    assert kb.delete_own("alice", "c0001") is False
    assert len(kb.retrieve("wire cut-off", "alice", k=3)) == 1


def test_delete_own_is_false_for_unknown_id():
    assert InMemoryKB().delete_own("alice", "nope") is False
