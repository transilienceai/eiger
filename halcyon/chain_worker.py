"""S4/S5 of the kill chain: the build worker that 'loads' the deployed artifact.

Phase 1 = StubWorker: an in-process, constrained emulation. It does NOT unpickle
anything; it emulates 'the poisoned artifact deserialized and ran attacker code'
and then runs only the one payload the capstone proves — read the per-session
vault master and exfiltrate it via the single allow-listed callback. Phase 2
swaps a real ephemeral egress-locked container behind this same Worker protocol.
"""
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from halcyon import audit
from halcyon.chain_state import ChainSession
from halcyon.config import Settings
from halcyon.store import Store


class Worker(Protocol):
    def run(
        self, session_id: str, session: ChainSession, store: Store, settings: Settings
    ) -> None: ...


@dataclass
class StubWorker:
    report: Callable[[str, str], None]

    def run(
        self, session_id: str, session: ChainSession, store: Store, settings: Settings
    ) -> None:
        # S4: the hardened loader (SEC_ARTIFACT_VERIFICATION) refuses a non-safetensors /
        # unpinned artifact, so it is never deserialized and no code runs.
        if settings.sec_artifact_verification:
            return
        audit.record(
            store, session_id, "chain", audit.MALICIOUS_ARTIFACT_LOADED, session_id,
            {"artifact_url": session.artifact_url},
        )
        # S5 constrained payload: read the per-session secret and exfil via the callback.
        # SEC_WORKER_SANDBOX = secret not mounted + egress blocked (defense-in-depth):
        # code still ran, but it cannot read or send the crown jewel.
        if settings.sec_worker_sandbox:
            return
        self.report(session_id, session.vault_master)
