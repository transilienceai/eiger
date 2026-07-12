import hashlib
import pickle  # noqa: S403 - deliberately vulnerable teaching path (vulnerable mode only)
from pathlib import Path

from halcyon.config import Settings


class ArtifactError(Exception):
    """Raised by the hardened loader when an artifact is refused."""


# Pinned sha256 allowlist of trusted safetensors artifacts (empty seed; ops adds hashes).
ALLOWED_HASHES: set[str] = set()


def sha256_file(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_artifact(path: str | Path, settings: Settings) -> object:
    if settings.sec_artifact_verification:
        p = Path(path)
        if p.suffix != ".safetensors":
            raise ArtifactError(f"refused: only .safetensors permitted, got '{p.suffix}'")
        digest = sha256_file(p)
        if digest not in ALLOWED_HASHES:
            raise ArtifactError(f"refused: {digest} not in pinned allowlist")
        return p.read_bytes()  # teaching stub: a real reader would parse safetensors
    # VULNERABLE: arbitrary deserialization — loading a poisoned artifact executes code.
    with open(path, "rb") as f:
        return pickle.load(f)  # noqa: S301
