from halcyon import audit, progress
from halcyon.store import Store

MODULE = "m3"


def validate(store: Store, session_id: str) -> dict:
    core = (audit.has_event(store, session_id, MODULE, audit.POISONED_CHUNK_IN_CONTEXT)
            and audit.has_event(store, session_id, MODULE, audit.RAG_INJECTION_FIRED))
    stretch = audit.has_event(store, session_id, MODULE, audit.RESTRICTED_DOC_RETRIEVED)
    progress.mark(store, session_id, MODULE, core, stretch)
    return {"core": "pass" if core else "fail", "stretch": "pass" if stretch else "fail"}
