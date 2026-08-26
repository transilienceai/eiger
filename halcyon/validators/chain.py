from halcyon import audit, progress
from halcyon.store import Store

MODULE = "chain"


def validate(store: Store, session_id: str, attacker_account: str) -> dict:
    events = store.events_since_reset(session_id, MODULE)
    seen = {e.event_type for e in events}
    # Deliberately no ordering check here (no first-occurrence ids, no
    # increasing-id assertion). S10's validator required strict ordering and
    # that produced two ways to permanently brick a legitimate run: an
    # unauthenticated callback that pinned the terminal event first, and a
    # click-race that inverted two ids. The coupling that would make ordering
    # meaningful is already enforced in code upstream of this module (no key,
    # no ingestion; no ingestion, nothing to retrieve) -- so an ordering
    # check here would only add brick paths, not security. Do not "restore"
    # one; see tests/test_validator_chain.py::test_out_of_order_events_still_pass.
    stages = {
        "key": audit.INGEST_KEY_ACCEPTED in seen,
        "ingested": audit.POLICY_DOC_INGESTED in seen,
        "retrieved": audit.POISONED_DOC_RETRIEVED in seen,
        "transferred": audit.TREASURY_TRANSFER_EXECUTED in seen,
    }
    # The only thing that grades: money moved to the account this session was
    # issued. Not "a transfer happened" -- theirs. Unforgeable, and it proves
    # they steered the assistant rather than merely disturbed it.
    core = any(
        e.event_type == audit.TREASURY_TRANSFER_EXECUTED
        and e.details.get("to_account") == attacker_account
        for e in events
    )
    marker_present = audit.CHAIN_CORE_PASSED in seen
    if core and not marker_present:
        # Record which account earned the pass. With no details this row is
        # indistinguishable from a participant-emitted one; at a live
        # conference a disputed grade or an instructor auditing the board
        # needs something to point at.
        audit.record(
            store,
            session_id,
            MODULE,
            audit.CHAIN_CORE_PASSED,
            session_id,
            {"to_account": attacker_account},
        )
    # A pass is a durable fact once earned. The marker lives inside the reset
    # epoch, so a module_reset drops it and genuinely retracts the pass, while a
    # stale re-validate (a redeploy rotated the assigned account) cannot erase it.
    durable = core or marker_present
    progress.mark(store, session_id, MODULE, durable, False)
    result: dict = {"core": "pass" if durable else "fail"}
    if durable:
        # `stages` names the four steps this capstone chains -- itself a
        # spoiler, since it hands over that "retrieved" is a distinct,
        # competitive step. This endpoint is the one thing a participant is
        # certain to hit directly (devtools Network tab, not just the panel),
        # so withholding it isn't a UI nicety -- it's the only place this can
        # actually be enforced. Include it only once there's nothing left to
        # spoil: the run already passed.
        result["stages"] = stages
    return result
