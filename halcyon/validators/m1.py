from halcyon import audit, progress
from halcyon.store import Store

MODULE = "m1"


def validate(store: Store, session_id: str) -> dict:
    core = audit.has_event(store, session_id, MODULE, audit.INTERNAL_TOKEN_DISCLOSED)
    stretch = audit.has_event(store, session_id, MODULE, audit.POLICY_OVERRIDE)
    progress.mark(store, session_id, MODULE, core, stretch)
    return {
        "core": "pass" if core else "fail",
        "stretch": "pass" if stretch else "fail",
    }
