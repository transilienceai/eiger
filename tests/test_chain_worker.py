from halcyon import audit
from halcyon.chain_state import ChainSession
from halcyon.chain_worker import StubWorker
from halcyon.config import load_settings
from halcyon.store import InMemoryStore

VULN = load_settings({"HALCYON_MODE": "vulnerable"})


def _sess():
    return ChainSession(
        ci_token="t", vault_master="VAULT-MASTER-42", artifact_url="http://x/evil.pkl"
    )


def _events(store, etype):
    return [e for e in store.events_since_reset("p1", "chain") if e.event_type == etype]


def test_vulnerable_run_loads_artifact_and_exfils_secret():
    store = InMemoryStore()
    seen: list[tuple[str, str]] = []
    w = StubWorker(report=lambda sid, secret: seen.append((sid, secret)))
    w.run("p1", _sess(), store, VULN)
    assert _events(store, audit.MALICIOUS_ARTIFACT_LOADED)
    assert seen == [("p1", "VAULT-MASTER-42")]


def test_artifact_verification_refuses_before_load():
    store = InMemoryStore()
    seen: list = []
    settings = load_settings({"HALCYON_MODE": "vulnerable", "SEC_ARTIFACT_VERIFICATION": "1"})
    w = StubWorker(report=lambda sid, secret: seen.append((sid, secret)))
    w.run("p1", _sess(), store, settings)
    assert _events(store, audit.MALICIOUS_ARTIFACT_LOADED) == []
    assert seen == []


def test_worker_sandbox_blocks_exfil_but_code_still_ran():
    store = InMemoryStore()
    seen: list = []
    settings = load_settings({"HALCYON_MODE": "vulnerable", "SEC_WORKER_SANDBOX": "1"})
    w = StubWorker(report=lambda sid, secret: seen.append((sid, secret)))
    w.run("p1", _sess(), store, settings)
    # code "ran" (artifact loaded) but the secret never leaves the sandbox
    assert _events(store, audit.MALICIOUS_ARTIFACT_LOADED)
    assert seen == []
