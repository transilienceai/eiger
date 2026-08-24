"""Read-only mock 'eiger-platform' repo for the S10 kill-chain S1 leak.

Deterministic, per-session: the leaked CI token is rendered into .env.sample at
serve time (blob), so a reset that regenerates the token changes what leaks with
no reseeding. The commit log tells a 'committed a token, reverted it' story that
lures the participant into git history to find it in .env.sample.
"""

LEAK_PATH = ".env.sample"
LEAK_COMMIT = "a1b2c3d"

_TREE = [
    ".env.sample",
    "README.md",
    "app.py",
    "deploy/ci.yml",
]

_LOG = [
    {"id": "f0091ac", "author": "ravi@eiger.test",
     "message": "chore: initial platform scaffold"},
    {"id": LEAK_COMMIT, "author": "ci-bot@eiger.test",
     "message": "Revert \"ci: hardcode deploy token in .env.sample (temporary)\" "
                "-- token left in sample env, rotate later"},
    {"id": "9d4e7b2", "author": "mira@eiger.test",
     "message": "feat: add /internal/deploy hook for the build worker"},
]

_BENIGN = {
    "README.md": "# eiger-platform\n\nInternal deployment tooling for Eiger.\n",
    "app.py": "def main() -> None:\n    print('eiger-platform')\n",
    "deploy/ci.yml": "steps:\n  - run: python app.py\n  - run: curl -X POST $DEPLOY_URL\n",
}


def tree() -> list[str]:
    return list(_TREE)


def log() -> list[dict]:
    return [dict(c) for c in _LOG]


def blob(path: str, ci_token: str) -> str:
    if path == LEAK_PATH:
        return (
            "# Sample environment for eiger-platform.\n"
            "# NOTE: copy to .env and fill real values in prod.\n"
            "DEPLOY_URL=http://build-worker.internal/internal/deploy\n"
            f"EIGER_CI_TOKEN={ci_token}\n"
        )
    return _BENIGN.get(path, "")
