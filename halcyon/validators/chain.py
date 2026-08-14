from halcyon import audit, progress
from halcyon.store import Store

MODULE = "chain"

ORDER = [
    audit.SECRET_LEAK_DISCOVERED,
    audit.MISCONFIG_EXPLOITED,
    audit.TRUSTED_INJECTION_FIRED,
    audit.MALICIOUS_ARTIFACT_LOADED,
    audit.RCE_CONFIRMED,
]


def validate(store: Store, session_id: str, vault_master: str) -> dict:
    events = store.events_since_reset(session_id, MODULE)
    first_id: dict[str, int] = {}
    for e in events:
        if e.event_type in ORDER and e.event_type not in first_id:
            first_id[e.event_type] = e.id
    stages = {et: (et in first_id) for et in ORDER}
    all_present = all(stages.values())
    in_order = all_present and all(
        first_id[ORDER[i]] < first_id[ORDER[i + 1]] for i in range(len(ORDER) - 1)
    )
    secret_ok = any(
        e.event_type == audit.RCE_CONFIRMED and e.details.get("secret") == vault_master
        for e in events
    )
    core = in_order and secret_ok
    progress.mark(store, session_id, MODULE, core, False)
    return {"core": "pass" if core else "fail", "stages": stages}
