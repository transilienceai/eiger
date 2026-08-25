import itertools

from halcyon import treasury_corpus
from halcyon.treasury_state import TreasuryProvider, TreasurySession


def _p():
    k = itertools.count(1)
    a = itertools.count(1)
    return TreasuryProvider(
        gen=lambda: f"key-{next(k)}",
        account_gen=lambda: f"90{next(a):02d}",
        scenarios=["vendor", "payroll", "wire", "escrow"],
    )


def test_session_gets_key_account_and_scenario():
    s = _p()("alice")
    assert isinstance(s, TreasurySession)
    assert s.ingest_key == "key-1"
    assert s.attacker_account == "9001"
    assert s.scenario in ("vendor", "payroll", "wire", "escrow")


def test_same_session_is_memoized():
    p = _p()
    assert p("alice") is p("alice")


def test_distinct_sessions_get_distinct_keys_and_accounts():
    p = _p()
    assert p("alice").ingest_key != p("bob").ingest_key
    assert p("alice").attacker_account != p("bob").attacker_account


def test_scenarios_vary_across_sessions():
    p = _p()
    seen = {p(f"s{i}").scenario for i in range(4)}
    assert len(seen) == 4, "each of the four scenarios should be handed out"


def test_reset_rotates_everything_and_replaces_the_session():
    p = _p()
    first = p("alice")
    second = p.reset("alice")
    assert second is not first
    assert second.ingest_key != first.ingest_key
    assert second.attacker_account != first.attacker_account
    assert p("alice") is second


def test_attacker_account_band_is_disjoint_from_every_legit_account():
    # treasury_state.py is deliberately dependency-free -- it takes scenario
    # keys as plain strings and never imports the corpus -- so it cannot
    # enforce this at runtime. This test enforces it instead: the real
    # account_gen() must never draw a value that collides with any scenario's
    # legit_account (treasury_corpus.py). A collision would let a participant
    # whose assigned account happened to match their scenario's legitimate
    # destination get graded "passed" for simply releasing the pending
    # payment through the front door -- no injection, no attack, free pass.
    # account_gen() draws secrets.randbelow(1000) + 9000 -- its whole output
    # domain is exactly range(9000, 10000). Assert disjointness against that
    # domain directly rather than a Monte-Carlo sample of it: a sample can
    # miss a rare single-value collision forever, while this is exhaustive
    # by construction and will also catch a future scenario minted with a
    # 9xxx legit_account.
    legit_accounts = {s.legit_account for s in treasury_corpus.SCENARIOS.values()}
    assert set(str(n) for n in range(9000, 10000)).isdisjoint(legit_accounts)
