from halcyon import audit, progress
from halcyon.store import Store

MODULE = "m7"


def validate(store: Store, session_id: str) -> dict:
    core = (audit.has_event(store, session_id, MODULE, audit.INTER_AGENT_INJECTION_PROPAGATED)
            and audit.has_event(store, session_id, MODULE, audit.UNAUTHORIZED_APPROVAL))
    stretch = audit.has_event(store, session_id, MODULE, audit.SUPERVISOR_PROVENANCE_BYPASSED)
    progress.mark(store, session_id, MODULE, core, stretch)
    return {
        "core": "pass" if core else "fail",
        "stretch": "pass" if stretch else "fail",
    }
