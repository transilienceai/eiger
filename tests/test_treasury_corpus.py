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


def test_brief_does_not_leak_the_query():
    # the participant sees `brief`; inferring `query` from it is the puzzle,
    # so the brief must not simply restate the query
    for k in tc.SCENARIO_KEYS:
        s = tc.SCENARIOS[k]
        assert s.query.lower() not in s.brief.lower()


def test_every_scenario_has_a_legit_account_and_amount():
    for k in tc.SCENARIO_KEYS:
        s = tc.SCENARIOS[k]
        assert s.legit_account and s.amount > 0
