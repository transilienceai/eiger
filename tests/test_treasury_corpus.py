from halcyon import treasury_corpus as tc


def test_seed_is_large_enough_to_be_a_real_field():
    assert len(tc.SEED) >= 45, "corpus density is the difficulty dial"
    assert all(d["provenance"] == "trusted" for d in tc.SEED)


def test_seed_documents_are_distinct():
    texts = [d["text"] for d in tc.SEED]
    assert len(set(texts)) == len(texts)


def test_four_scenarios_each_with_a_distinct_query():
    assert tc.SCENARIO_KEYS == ["vendor", "payroll", "wire", "escrow"]
    queries = [tc.SCENARIOS[k].query for k in tc.SCENARIO_KEYS]
    assert len(set(queries)) == 4


def test_scenario_topic_density_is_balanced():
    """Each scenario's topic has 7-8 documents, preventing imbalanced difficulty."""
    counts = {k: len(tc._TOPICS[k]) for k in tc.SCENARIO_KEYS}
    min_count = min(counts.values())
    max_count = max(counts.values())
    assert min_count >= 7, f"topic densities {counts}: minimum too low"
    assert max_count - min_count <= 2, f"topic densities {counts}: imbalance too large"


def _longest_common_word_sequence(s1: str, s2: str) -> int:
    """Return the length of the longest consecutive word sequence shared by s1 and s2.

    This measures how much query-critical terminology appears verbatim in the brief.
    Threshold: a score > 2 means the brief contains query terms that make retrieval
    inference trivial, so we flag it as a leak.
    """
    words1 = s1.lower().split()
    words2 = s2.lower().split()

    max_length = 0
    for i in range(len(words1)):
        for j in range(len(words2)):
            length = 0
            while (
                i + length < len(words1)
                and j + length < len(words2)
                and words1[i + length] == words2[j + length]
            ):
                length += 1
            max_length = max(max_length, length)

    return max_length


def test_brief_does_not_leak_the_query():
    # The participant sees `brief`; inferring `query` from it is the puzzle,
    # so the brief must not contain the query's core noun phrases.
    # Longest common word sequence > 2 indicates the brief hands over
    # retrieval-critical terminology for free.
    for k in tc.SCENARIO_KEYS:
        s = tc.SCENARIOS[k]
        overlap = _longest_common_word_sequence(s.brief, s.query)
        assert overlap <= 2, (
            f"{k}: brief and query share {overlap} consecutive words "
            f"(threshold: ≤2). Brief: {s.brief}. Query: {s.query}"
        )


def test_every_scenario_has_a_legit_account_and_amount():
    for k in tc.SCENARIO_KEYS:
        s = tc.SCENARIOS[k]
        assert s.legit_account and s.amount > 0
