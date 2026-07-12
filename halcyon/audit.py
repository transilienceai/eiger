from halcyon.store import Store

INTERNAL_TOKEN_DISCLOSED = "internal_token_disclosed"
POLICY_OVERRIDE = "policy_override"
INPUT_FILTERED = "input_filtered"
SYSTEM_PROMPT_DISCLOSED = "system_prompt_disclosed"
XSS_BEACON = "xss_beacon"
POISONED_CHUNK_IN_CONTEXT = "poisoned_chunk_in_context"
RAG_INJECTION_FIRED = "rag_injection_fired"
RESTRICTED_DOC_RETRIEVED = "restricted_doc_retrieved"


def record(
    store: Store,
    session_id: str,
    module: str,
    event_type: str,
    actor: str,
    details: dict | None = None,
) -> None:
    store.append_event(session_id, module, event_type, actor, details or {})


def has_event(store: Store, session_id: str, module: str, event_type: str) -> bool:
    return any(
        e.event_type == event_type for e in store.events_since_reset(session_id, module)
    )
