"""Mirrors tests/test_kb_manage.py's scoping bypass matrix against ChromaKB.

test_kb_manage.py only exercises InMemoryKB, whose list_own/delete_own scoping
is a plain Python list comprehension over an in-process list. Production runs
ChromaKB, whose scoping is a completely different code path -- a Chroma
`where={"$and": [...]}` metadata filter (see halcyon/chroma_kb.py). The two
implementations could silently drift (a bug in the Chroma `$and` clause, for
instance, would never be caught by the InMemoryKB-only matrix), so this file
re-runs the same bypass attempts against the real backend.

Needs the baked ONNX embedding model, like the rest of the calibration suite
-- see tests/test_calibration.py's module docstring for why this is
container-only and excluded from the default run.
"""
import pytest

from halcyon.chroma_kb import ChromaKB

pytestmark = pytest.mark.calibration


def _kb() -> ChromaKB:
    # One shared collection name, cleared before every test: clear() drops
    # and recreates the Chroma collection, so each test starts from the same
    # known-empty state as InMemoryKB()'s fresh instance in the mirrored file.
    kb = ChromaKB(collection="calib-kb-manage-bypass")
    kb.clear()
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
    # the seeded chunk is c0001 -- deleting it would empty the field the
    # participant is supposed to compete against
    assert kb.delete_own("alice", "c0001") is False
    # Unlike InMemoryKB.retrieve (token overlap, zero-score matches dropped),
    # ChromaKB.retrieve always returns up to k nearest neighbours regardless
    # of relevance -- so this checks the seed text is still THERE, not an
    # exact result count, which is the ChromaKB-accurate form of the same
    # assertion.
    hits = kb.retrieve("wire cut-off", "alice", k=3)
    assert "Wire cut-off is 16:00 local." in [c.text for c in hits]


def test_delete_own_is_false_for_unknown_id():
    assert _kb().delete_own("alice", "nope") is False
