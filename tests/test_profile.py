from halcyon.store import InMemoryStore


def test_profile_roundtrip_default_empty():
    s = InMemoryStore()
    assert s.get_profile("p1") == ""
    s.set_profile("p1", "<b>x</b>")
    assert s.get_profile("p1") == "<b>x</b>"
