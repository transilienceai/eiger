from halcyon import audit, progress
from halcyon.store import InMemoryStore
from halcyon.validators import m4


def test_core_fail_when_no_event():
    s = InMemoryStore()
    assert m4.validate(s, "p1") == {"core": "fail", "stretch": "fail"}


def test_core_pass_after_malicious_artifact_event():
    s = InMemoryStore()
    audit.record(s, "p1", "m4", audit.MALICIOUS_ARTIFACT_IDENTIFIED, "p1")
    assert m4.validate(s, "p1") == {"core": "pass", "stretch": "fail"}
    assert progress.read(s, "p1", "m4") == (True, False)


def test_stretch_pass_on_vulnerable_dependency_event():
    s = InMemoryStore()
    audit.record(s, "p1", "m4", audit.VULNERABLE_DEPENDENCY_IDENTIFIED, "p1")
    result = m4.validate(s, "p1")
    assert result["stretch"] == "pass"
