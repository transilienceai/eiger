"""Citations for seeded treasury policy documents.

A participant's only diagnostic after a review is the citation list: their
own document present means it ranked, absent means it didn't. Seeded
documents can't cite their own text (see test_treasury_agent.py and
test_web_treasury.py for why -- `/api/treasury/review` takes no key, so
returning seed text in any form hands over the ranking payload for free).
These tests cover the reference that stands in for that text instead: it
must look like a real citation, stay put across calls, differ between
documents, and never repeat a word the document it names actually uses.
"""
import re

from halcyon import treasury_agent, treasury_corpus
from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.kb import InMemoryKB
from halcyon.llm import FinalAnswer, StubToolLLM
from halcyon.store import InMemoryStore
from halcyon.treasury_state import TreasurySession

VULN = load_settings({"HALCYON_MODE": "vulnerable"})


def _fixture(scenario_key: str = "vendor"):
    kb = InMemoryKB()
    kb.seed(treasury_corpus.SEED)
    bank = Bank()
    store = InMemoryStore()
    session = TreasurySession(ingest_key="k", attacker_account="9931", scenario=scenario_key)
    return kb, bank, store, session


def _content_words(text: str) -> set[str]:
    """Alphabetic tokens only -- numbers (section digits, revision years) are
    generic filing furniture, not vocabulary a participant could use to
    infer what a document is about."""
    return set(re.findall(r"[a-z]+", text.lower()))


def test_no_seeded_text_appears_in_the_review_response_for_any_scenario():
    seed_texts = {f["text"] for f in treasury_corpus.SEED}
    for key in treasury_corpus.SCENARIO_KEYS:
        kb, bank, store, session = _fixture(key)
        llm = StubToolLLM([FinalAnswer("declined")])
        _, cited, _ = treasury_agent.review(llm, "p1", session, kb, bank, store, VULN)
        assert not (set(cited) & seed_texts), f"scenario {key!r} leaked seed text"


def test_seeded_citation_is_stable_across_calls():
    for doc in treasury_corpus.SEED:
        text = doc["text"]
        first = treasury_agent.seeded_citation(text)
        second = treasury_agent.seeded_citation(text)
        assert first == second


def test_seeded_citations_are_distinct_across_the_corpus():
    refs = [treasury_agent.seeded_citation(d["text"]) for d in treasury_corpus.SEED]
    assert len(set(refs)) == len(refs), "two seeded documents produced the same citation"


def test_no_seeded_citation_contains_a_content_word_from_its_own_document():
    for doc in treasury_corpus.SEED:
        text = doc["text"]
        ref = treasury_agent.seeded_citation(text)
        leaked = _content_words(ref) & _content_words(text)
        assert not leaked, f"citation {ref!r} leaks word(s) {leaked} from its own document"


def test_own_upload_still_renders_verbatim_alongside_seeded_citations():
    kb, bank, store, session = _fixture()
    mine = "supplier invoice settlement release vendor approval policy"
    kb.add(mine, "user", owner_session="p1")
    llm = StubToolLLM([FinalAnswer("declined")])
    _, cited, _ = treasury_agent.review(llm, "p1", session, kb, bank, store, VULN)
    assert mine in cited
