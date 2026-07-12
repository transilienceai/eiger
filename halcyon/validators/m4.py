from halcyon import audit, progress
from halcyon.store import Store

MODULE = "m4"


def validate(store: Store, session_id: str) -> dict:
    core = audit.has_event(store, session_id, MODULE, audit.MALICIOUS_ARTIFACT_IDENTIFIED)
    stretch = audit.has_event(store, session_id, MODULE, audit.VULNERABLE_DEPENDENCY_IDENTIFIED)
    progress.mark(store, session_id, MODULE, core, stretch)
    return {
        "core": "pass" if core else "fail",
        "stretch": "pass" if stretch else "fail",
    }
