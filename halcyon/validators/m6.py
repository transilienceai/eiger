from halcyon import audit, progress
from halcyon.store import Store

MODULE = "m6"


def validate(store: Store, session_id: str) -> dict:
    core = audit.has_event(store, session_id, MODULE, audit.MCP_POISONED_INVOCATION)
    stretch = (audit.has_event(store, session_id, MODULE, audit.MCP_DESC_MUTATION_ACCEPTED)
               or audit.has_event(store, session_id, MODULE, audit.TOKEN_READ))
    progress.mark(store, session_id, MODULE, core, stretch)
    return {
        "core": "pass" if core else "fail",
        "stretch": "pass" if stretch else "fail",
    }
