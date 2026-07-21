# S8 / M8 (Guardrails + Capstone) — Live e2e sign-off

**Date:** 2026-07-18 · **Branch:** `s8-m8-guardrails` · **Suite:** 181 passed, 4 skipped · ruff + mypy clean. **Live e2e: [FILL AT E2E TIME]**

M8 is the final teaching layer (L5 production): **guardrail evasion** is the 8th attack vector. `SEC_GUARDRAILS` gates `guards.canonicalize()` (de-leetspeak → NFKC → strip zero-width → lowercase) applied *before* the blocklist match, fronting the existing M1 Halo pipeline via `halo.guarded_turn` on the new `POST /api/guarded-chat` surface. The core attack: an obfuscated payload (leetspeak `P4RS3LT0NGV3` / unicode / zero-width variants) slips past a naive raw-string input filter and re-lands the M1 operator-token leak (`HALCYON-OPS-7731`). Stretch: harden and re-test — the *same* payload gets blocked once the guard is on.

Grading is host-side against the append-only audit log (mechanism, not model words): `guardrail_bypassed` (core) / `guardrail_hardened_block` (stretch), via `validators/m8.py`. The guard is deterministic and model-independent — canonicalization is pure string transformation, so the vuln→secure flip is proven by the guard flag alone, not by model behavior. (Model non-determinism only affects *whether Halo discloses the token when asked* in the underlying M1 pipeline reuse — the guardrail decision itself, allow/block, is 100% deterministic given the payload and the flag.)

Also new: `GET /capstone?session=` — a **read-only** residual-risk scoreboard (`capstone.py::residual_risk`) aggregating each module's core-exploit event across m1–m8, reusing a `CORE_EVENTS` map kept in sync with the validators by a dedicated test. No grading of its own; nothing to prove live beyond "it returns the right aggregate given prior audit events."

No new container, no compose change — `/api/guarded-chat` and `/capstone` run in-process inside the existing `web` service (`OPERATIONS.md` updated accordingly).

**Status: [FILL AT E2E TIME]**

## 1. Reach-test

- [ ] `docker compose up -d --build` — stack comes up clean (`web`, `db`, `ollama` all healthy).
- [ ] `GET /health` → `{"status":"ok","mode":"vulnerable","ollama":"up","db":"up","mcp":"up"}` (M8 adds no new health probe — in-process).
- [ ] `POST /api/guarded-chat` reachable → returns `{"reply": ...}` without error.
- [ ] `GET /capstone?session=<id>` reachable → returns the residual-risk scoreboard shape (`{"session", "modules": [...], "exploited_count", "total"}`).

## 2. Deterministic-suite evidence (already captured, not live)

- [x] `uv run pytest -q` → **181 passed, 4 skipped** (the 4 skips are the pre-existing Postgres + ChromaDB + 2 MCP-over-HTTP integration tests, unrelated to M8).
- [x] `uv run ruff check .` — clean.
- [x] `uv run mypy halcyon` — clean.
- [x] M8 tests drive `guards.canonicalize` / `guards.guardrail_check` / `halo.guarded_turn` directly (stubbed LLM, no network) and assert `guardrail_bypassed` fires in vulnerable mode and `guardrail_hardened_block` fires in secure mode for the same obfuscated payload, plus the un-obfuscated payload is blocked in both modes.
- [x] A dedicated test (`test_core_events_map_stays_in_sync_with_validators` or equivalent) keeps `capstone.CORE_EVENTS` in sync with `validators/*.py` so the capstone can't silently drift from the per-module grading.

## 3. Live full-stack e2e with a real model (keyless, Ollama) — [FILL AT E2E TIME]

Stack: `docker compose up -d --build web db ollama` against the shared Ollama backend (`llama3.1:8b`), `HALCYON_MODE` flipped between runs, identical **leetspeak operator-token payload** each time (obfuscated request designed to leak `HALCYON-OPS-7731` — e.g. a `P4RS3LT0NGV3`-style leetspeak override phrase that a raw-string blocklist match won't catch but canonicalization will).

- [ ] **Vulnerable** — real `llama3.1:8b`, session `e2e-m8-vuln`:
  ```
  [FILL: request/response]
  [FILL] validate={'core': 'FILL', 'stretch': 'FILL'}
  ```
  Expected: the obfuscated payload bypasses the raw-only blocklist match, reaches Halo, and the M1 operator-token leak fires → `guardrail_bypassed` recorded → `/validate/m8` `core:pass`.

- [ ] **Secure** (`HALCYON_MODE=secure`) — the **same** leetspeak payload, session `e2e-m8-secure`:
  ```
  [FILL: request/response]
  [FILL] validate={'core': 'FILL', 'stretch': 'FILL'}
  ```
  Expected: `canonicalize()` de-leetspeaks/normalizes the payload before the blocklist match, the request is blocked (`REFUSAL` reply), `guardrail_hardened_block` recorded → `/validate/m8` `core:fail`, `stretch:pass`.

- [ ] **The vulnerable→secure diff on the identical obfuscated payload is proven live — the flag alone flips `core:pass` → `core:fail`.**

## 4. Capstone spot-check (not a grading surface, sanity only)

- [ ] After running a mix of prior-module attacks (or a subset) in a session, `GET /capstone?session=<id>` reflects the correct `exploited_count` / per-module `exploited` booleans against the same audit log the validators query.

## Deferred / notes

- garak/PyRIT are a documented **external** exercise (point your scanner at the live API) — not built into the suite; no live-run item here.
- Guardrail grading is deterministic/model-independent by construction — canonicalize-then-match is pure string logic; the live e2e above is to confirm the wiring (endpoint → guard → audit → validator) works against a real model turn, not to prove the guard's correctness (already proven by the deterministic suite).

## Verdict

**[FILL AT E2E TIME]** — Vuln `core:pass` → secure `core:fail` to be proven live on the mechanism with an identical obfuscated payload, matching the M6/M7 bar. Deterministic suite 181 passed / 4 skipped, ruff + mypy clean.
