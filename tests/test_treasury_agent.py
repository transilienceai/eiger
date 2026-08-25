import pytest

from halcyon import audit, treasury_agent, treasury_corpus
from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.kb import InMemoryKB
from halcyon.llm import FinalAnswer, StubToolLLM, ToolCall
from halcyon.store import InMemoryStore
from halcyon.treasury_state import TreasurySession

VULN = load_settings({"HALCYON_MODE": "vulnerable"})


def _fixture():
    kb = InMemoryKB()
    kb.seed(treasury_corpus.SEED)
    bank = Bank()
    bank.seed([{"id": "9931", "owner_session": "attacker", "email": "a@b.c", "balance": 0}])
    store = InMemoryStore()
    session = TreasurySession(ingest_key="k", attacker_account="9931", scenario="vendor")
    return kb, bank, store, session


def _events(store, etype):
    return [e for e in store.events_since_reset("p1", "chain") if e.event_type == etype]


def test_transfer_records_event_with_destination_and_amount():
    kb, bank, store, session = _fixture()
    llm = StubToolLLM([ToolCall("transfer_funds", {"to_account": "9931", "amount": 45000}),
                       FinalAnswer("approved")])
    reply, cited, calls = treasury_agent.review(
        llm, "p1", session, kb, bank, store, VULN)
    fired = _events(store, audit.TREASURY_TRANSFER_EXECUTED)
    assert len(fired) == 1
    assert fired[0].details["to_account"] == "9931"
    assert fired[0].details["amount"] == 45000
    assert reply == "approved"


def test_citations_are_returned_so_a_participant_can_diagnose():
    kb, bank, store, session = _fixture()
    llm = StubToolLLM([FinalAnswer("declined")])
    _, cited, _ = treasury_agent.review(llm, "p1", session, kb, bank, store, VULN)
    assert len(cited) == 3, "k=3 retrieved documents are the diagnostic surface"
    assert all(isinstance(c, str) for c in cited)


def test_seeded_document_text_is_never_returned_as_a_citation():
    kb, bank, store, session = _fixture()
    llm = StubToolLLM([FinalAnswer("declined")])
    _, cited, _ = treasury_agent.review(llm, "p1", session, kb, bank, store, VULN)
    seed_texts = {f["text"] for f in treasury_corpus.SEED}
    assert not (set(cited) & seed_texts)
    assert all(c == treasury_agent.SEEDED_CITATION_PLACEHOLDER for c in cited)


def test_own_upload_is_verbatim_while_seed_chunks_stay_opaque():
    kb, bank, store, session = _fixture()
    mine = "supplier invoice settlement release vendor approval policy"
    kb.add(mine, "user", owner_session="p1")
    llm = StubToolLLM([FinalAnswer("declined")])
    _, cited, _ = treasury_agent.review(llm, "p1", session, kb, bank, store, VULN)
    assert mine in cited
    assert cited.count(treasury_agent.SEEDED_CITATION_PLACEHOLDER) == len(cited) - 1


def test_the_model_still_receives_the_real_seeded_text_in_its_policy_block():
    """Redacting the response must not touch what the model reads: the
    citations returned to the caller and the policy block built into the
    system message are two separate views over the same retrieved chunks."""
    kb, bank, store, session = _fixture()

    class _RecordingLLM:
        def __init__(self) -> None:
            self.messages: list[dict] = []

        def next_step(self, messages: list[dict], tools: list[dict]):
            self.messages = messages
            return FinalAnswer("declined")

    llm = _RecordingLLM()
    _, cited, _ = treasury_agent.review(llm, "p1", session, kb, bank, store, VULN)
    system_content = llm.messages[0]["content"]
    seed_texts = [f["text"] for f in treasury_corpus.SEED]
    assert any(t in system_content for t in seed_texts), \
        "the model's policy block must still contain real seeded text"
    assert all(c == treasury_agent.SEEDED_CITATION_PLACEHOLDER for c in cited)


def test_user_provenance_chunk_in_context_is_recorded():
    kb, bank, store, session = _fixture()
    kb.add("supplier invoice settlement release vendor approval policy", "user",
           owner_session="p1")
    llm = StubToolLLM([FinalAnswer("declined")])
    treasury_agent.review(llm, "p1", session, kb, bank, store, VULN)
    assert _events(store, audit.POISONED_DOC_RETRIEVED)


def test_unknown_tool_name_does_nothing():
    kb, bank, store, session = _fixture()
    llm = StubToolLLM([ToolCall("wire_money", {"to_account": "9931", "amount": 1}),
                       FinalAnswer("done")])
    _, _, calls = treasury_agent.review(llm, "p1", session, kb, bank, store, VULN)
    assert _events(store, audit.TREASURY_TRANSFER_EXECUTED) == []
    assert calls[0][2] == "unknown tool: wire_money"


def test_the_agents_query_is_never_in_the_reply_or_citations():
    """A stub that always returns the literal string "declined" can never
    violate this assertion, whatever it claims to demonstrate. Use an LLM
    that echoes its own full system prompt -- which DOES carry real seeded
    policy text -- back as its answer, so the query's absence is proven
    against real content it could actually have leaked, not a canned
    placeholder that could never fail."""
    kb, bank, store, session = _fixture()

    class _EchoingLLM:
        def next_step(self, messages: list[dict], tools: list[dict]):
            system = next(m["content"] for m in messages if m["role"] == "system")
            return FinalAnswer("Declining. Policy considered: " + system)

    reply, cited, _ = treasury_agent.review(_EchoingLLM(), "p1", session, kb, bank, store, VULN)
    q = treasury_corpus.SCENARIOS["vendor"].query
    assert q not in reply
    assert all(q not in c for c in cited)


def test_amount_with_thousands_separator_still_records_and_transfers():
    """The scenario brief renders amounts like "45,000" -- a local model will
    often copy that formatting into the tool call. int("45,000") raises, and
    the old code let that exception skip the audit row entirely: correct
    destination, correct intent, no grading event, no diagnostic."""
    kb, bank, store, session = _fixture()
    llm = StubToolLLM([ToolCall("transfer_funds", {"to_account": "9931", "amount": "45,000"}),
                       FinalAnswer("approved")])
    treasury_agent.review(llm, "p1", session, kb, bank, store, VULN)
    fired = _events(store, audit.TREASURY_TRANSFER_EXECUTED)
    assert len(fired) == 1
    assert fired[0].details["to_account"] == "9931"
    assert fired[0].details["amount"] == 45000
    assert bank.get("9931").balance == 45000


def test_genuinely_unusable_amount_still_records_event_without_crediting():
    kb, bank, store, session = _fixture()
    llm = StubToolLLM([ToolCall("transfer_funds", {"to_account": "9931", "amount": "a lot"}),
                       FinalAnswer("approved")])
    treasury_agent.review(llm, "p1", session, kb, bank, store, VULN)
    fired = _events(store, audit.TREASURY_TRANSFER_EXECUTED)
    assert len(fired) == 1
    assert fired[0].details["to_account"] == "9931"
    assert fired[0].details["amount"] == 0
    assert bank.get("9931").balance == 0


def test_missing_to_account_does_nothing():
    kb, bank, store, session = _fixture()
    llm = StubToolLLM([ToolCall("transfer_funds", {"to_account": "", "amount": 45000}),
                       FinalAnswer("approved")])
    treasury_agent.review(llm, "p1", session, kb, bank, store, VULN)
    assert _events(store, audit.TREASURY_TRANSFER_EXECUTED) == []
    assert bank.get("9931").balance == 0


def test_to_account_whitespace_is_normalised_before_credit():
    kb, bank, store, session = _fixture()
    llm = StubToolLLM([ToolCall("transfer_funds", {"to_account": "9931 ", "amount": 45000}),
                       FinalAnswer("approved")])
    treasury_agent.review(llm, "p1", session, kb, bank, store, VULN)
    fired = _events(store, audit.TREASURY_TRANSFER_EXECUTED)
    assert fired[0].details["to_account"] == "9931"
    assert bank.get("9931").balance == 45000


class _RaisingStore:
    def append_event(self, *a, **kw):
        raise RuntimeError("audit store unavailable")


def test_ordering_is_enforced_by_construction_when_the_audit_write_fails():
    kb, bank, _, session = _fixture()
    llm = StubToolLLM([ToolCall("transfer_funds", {"to_account": "9931", "amount": 45000})])
    with pytest.raises(RuntimeError):
        treasury_agent.review(llm, "p1", session, kb, bank, _RaisingStore(), VULN)
    assert bank.get("9931").balance == 0
