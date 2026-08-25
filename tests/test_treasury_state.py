import itertools

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
