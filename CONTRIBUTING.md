# Contributing to Eiger

Eiger is a deliberately vulnerable teaching lab, so a useful contribution must preserve
both sides of each lesson: the attack should remain understandable and reproducible in
Vulnerable mode, and the paired control should remain small and visible in Hardened mode.

## Before opening a change

- For a bug or teaching improvement, open an issue describing the learner outcome and the
  affected module.
- For unintended security problems, follow `SECURITY.md` instead of publishing exploit
  details in an issue.
- Keep all fixtures synthetic. Never contribute real credentials, customer information,
  proprietary course material, or payloads aimed at real systems.
- Do not make the default deployment more reachable. Host ports must remain loopback-only;
  external access belongs in an explicit, isolated classroom configuration.

## Development setup

Eiger requires Python 3.12 and `uv` for development:

```bash
uv sync --locked --dev
uv run pytest -q
uv run ruff check .
uv run mypy halcyon
```

The full application runs with Docker Compose:

```bash
docker compose up -d --build
docker compose exec ollama ollama pull llama3.1:8b
```

See `OPERATIONS.md` before changing any network binding.

## Pull requests

- Keep one conceptual change per pull request.
- Add or update deterministic tests. Network-backed model tests should remain explicitly
  gated and must not be required for the default suite.
- Preserve mechanism-based validation: graders should query audit events, not model prose.
- For a security-control change, demonstrate the same input succeeding in Vulnerable mode
  and being blocked in Hardened mode without breaking the legitimate feature.
- Update the learner, trainer, or operations documentation when behavior changes.
- Confirm pytest, Ruff, mypy, and `docker compose config -q` pass before requesting review.

By contributing, you agree that your contribution is licensed under the repository's MIT
license.
