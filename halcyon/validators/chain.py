from halcyon import audit, progress
from halcyon.store import Store

MODULE = "chain"

ORDER = [
    audit.INGEST_KEY_ACCEPTED,
    audit.POLICY_DOC_INGESTED,
    audit.POISONED_DOC_RETRIEVED,
    audit.TREASURY_TRANSFER_EXECUTED,
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
        e.event_type == audit.TREASURY_TRANSFER_EXECUTED and e.details.get("secret") == vault_master
        for e in events
    )
    core = in_order and secret_ok
    marker_already_recorded = any(e.event_type == audit.CHAIN_CORE_PASSED for e in events)

    # A pass is a durable fact once earned: record it as an audit-log event
    # (once per reset-epoch) so a later stale observation -- e.g. a redeploy
    # rotates vault_master, so `secret_ok` goes False on the very same
    # events -- can't erase it. A genuine module_reset drops every event
    # before it, including this marker, from `events_since_reset`, so a
    # reset still retracts the pass with no extra bookkeeping, and a
    # post-reset replay is judged purely on what happened after the reset.
    # This keeps grading a pure query over the append-only audit log.
    if core and not marker_already_recorded:
        audit.record(store, session_id, MODULE, audit.CHAIN_CORE_PASSED, session_id)
    durable_core = core or marker_already_recorded

    progress.mark(store, session_id, MODULE, durable_core, False)
    # Ruling (fix round 1): the headline `core` reports durable_core, not this
    # call's live `core` observation. A container redeploy rotates vault_master
    # (in-process, un-persisted), which flips `secret_ok` to False against the
    # very same durable audit events -- without this, a participant who already
    # earned the pass would see a false "fail" here while the board (reading
    # the CHAIN_CORE_PASSED marker) still correctly shows pass. `stages` stays
    # a live read of the current reset-epoch -- only this headline is durable.
    return {"core": "pass" if durable_core else "fail", "stages": stages}
