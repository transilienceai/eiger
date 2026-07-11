from halcyon import audit, progress
from halcyon.store import InMemoryStore
from halcyon.validators import m1


def test_core_fail_when_no_disclosure():
    s = InMemoryStore()
    assert m1.validate(s, "p1") == {"core": "fail", "stretch": "fail"}


def test_core_pass_after_disclosure_and_progress_upserted():
    s = InMemoryStore()
    audit.record(s, "p1", "m1", audit.INTERNAL_TOKEN_DISCLOSED, "p1")
    assert m1.validate(s, "p1") == {"core": "pass", "stretch": "fail"}
    assert progress.read(s, "p1", "m1") == (True, False)


def test_stretch_pass_on_policy_override():
    s = InMemoryStore()
    audit.record(s, "p1", "m1", audit.POLICY_OVERRIDE, "p1")
    result = m1.validate(s, "p1")
    assert result["stretch"] == "pass"
