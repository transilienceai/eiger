from halcyon.store import InMemoryStore


def test_append_and_query_events():
    s = InMemoryStore()
    s.append_event("p1", "m1", "internal_token_disclosed", "p1", {})
    events = s.events_since_reset("p1", "m1")
    assert len(events) == 1
    assert events[0].event_type == "internal_token_disclosed"


def test_events_isolated_by_session_and_module():
    s = InMemoryStore()
    s.append_event("p1", "m1", "x", "p1", {})
    assert s.events_since_reset("p2", "m1") == []
    assert s.events_since_reset("p1", "m2") == []


def test_reset_marker_hides_earlier_events():
    s = InMemoryStore()
    s.append_event("p1", "m1", "internal_token_disclosed", "p1", {})
    s.write_reset_marker("p1", "m1")
    assert s.events_since_reset("p1", "m1") == []


def test_events_after_reset_are_visible():
    s = InMemoryStore()
    s.append_event("p1", "m1", "old", "p1", {})
    s.write_reset_marker("p1", "m1")
    s.append_event("p1", "m1", "new", "p1", {})
    events = s.events_since_reset("p1", "m1")
    assert [e.event_type for e in events] == ["new"]


def test_progress_defaults_false_then_upserts():
    s = InMemoryStore()
    assert s.get_progress("p1", "m1") == (False, False)
    s.upsert_progress("p1", "m1", True, False)
    assert s.get_progress("p1", "m1") == (True, False)
