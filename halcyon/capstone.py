from halcyon import audit
from halcyon.store import Store

# Each module's core-exploit signal — mirrors the core condition in validators/*.py.
# The test test_core_events_map_stays_in_sync_with_validators guards against drift.
CORE_EVENTS: dict[str, list[str]] = {
    "m1": [audit.INTERNAL_TOKEN_DISCLOSED],
    "m2": [audit.XSS_BEACON],
    "m3": [audit.POISONED_CHUNK_IN_CONTEXT, audit.RAG_INJECTION_FIRED],
    "m4": [audit.MALICIOUS_ARTIFACT_IDENTIFIED],
    "m5": [audit.UNAUTHORIZED_TOOL_CALL],
    "m6": [audit.MCP_POISONED_INVOCATION],
    "m7": [audit.INTER_AGENT_INJECTION_PROPAGATED, audit.UNAUTHORIZED_APPROVAL],
    "m8": [audit.GUARDRAIL_BYPASSED],
    # S10 capstone: keyed on the durable CHAIN_CORE_PASSED marker (written once by
    # validators.chain.validate on a genuine pass), not a raw stage event -- that's
    # the correct signal for "this session cracked the whole chain," and it stays
    # true even across a redeploy that rotates vault_master (see validators/chain.py).
    "chain": [audit.CHAIN_CORE_PASSED],
}

_LAYERS = {
    "m1": "L0 chatbot", "m2": "L0 chatbot", "m3": "L1 RAG", "m4": "ML supply chain",
    "m5": "L2 agent", "m6": "L3 MCP", "m7": "L4 multi-agent", "m8": "L5 guardrail",
    "chain": "Capstone",
}
_ATTACKS = {
    "m1": "operator-token leak", "m2": "stored XSS", "m3": "RAG injection",
    "m4": "poisoned artifact", "m5": "confused-deputy refund", "m6": "MCP tool poisoning",
    "m7": "inter-agent approval", "m8": "guardrail bypass", "chain": "kill-chain exfil",
}


def residual_risk(store: Store, session_id: str) -> dict:
    modules = []
    for module, events in CORE_EVENTS.items():
        exploited = all(audit.has_event(store, session_id, module, e) for e in events)
        modules.append({
            "module": module, "layer": _LAYERS[module],
            "attack": _ATTACKS[module], "exploited": exploited,
        })
    exploited_count = sum(1 for m in modules if m["exploited"])
    return {"session": session_id, "modules": modules,
            "exploited_count": exploited_count, "total": len(modules)}


def board(store: Store) -> dict:
    """Class-wide captured-attacks board: every session that landed at least one core
    exploit, most-cracked first. Hosted-only (needs the shared audit log)."""
    sessions = [
        rr
        for sid in store.list_sessions()
        if (rr := residual_risk(store, sid))["exploited_count"] > 0
    ]
    sessions.sort(key=lambda r: r["exploited_count"], reverse=True)
    return {"sessions": sessions, "total": len(sessions)}
