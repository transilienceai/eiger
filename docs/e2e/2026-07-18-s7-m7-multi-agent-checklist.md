# S7 / M7 (Multi-Agent) — Live e2e sign-off

**Date:** 2026-07-18 · **Branch:** `s7-m7-multi-agent` · **Suite:** 154 passed, 4 skipped · ruff + mypy clean.

M7 puts a real **LangGraph** `StateGraph` (`intake → risk → action → supervisor`) behind `POST /api/dispute`. Grading is host-side against the append-only audit log (mechanism, not model words): the core attack is cascading injection — a customer-supplied `dispute_text` payload propagates across implicitly-trusted agents, and the action agent auto-approves a fraudulent refund to `acct-attacker`, an account the session doesn't own. Stretch: the supervisor rubber-stamps the fraudulent action instead of catching it. `SEC_INTER_AGENT_AUTH` bundles the guard (HMAC sign+verify inter-agent messages, quarantine of untrusted dispute-text, supervisor provenance + `authorize_approval` ownership check).

No new container, no compose change — `/api/dispute` runs in-process inside the existing `web` service (`OPERATIONS.md` updated accordingly). There is no UI panel for M7 yet (API-only surface); reach-test below is a `curl`/`/health`-level check, not a chat-panel click-through.

**Status: this checklist is a scaffold. The live-run sections below are unfilled — do not merge until they're checked off with real evidence (per the "no merge without e2e" gate).**

## 1. Reach-test

- [ ] `docker compose up -d --build` — stack comes up clean (`web`, `db`, `ollama`; M6's `mcp-core-banking`/`mcp-crm` present but unrelated to M7).
- [ ] `GET /health` → `{"status":"ok", ...}` (M7 adds no new health probe — in-process, nothing external to check).
- [ ] `POST /api/dispute` reachable with a trivial benign body → returns `{"decision": ..., "transcript": [...]}` without error.

## 2. Deterministic-suite evidence (already captured, not live)

- [x] `uv run pytest -q` → **154 passed, 4 skipped** (the 4 skips are the pre-existing Postgres + ChromaDB + 2 MCP-over-HTTP integration tests, unrelated to M7).
- [x] `uv run ruff check .` — clean.
- [x] `uv run mypy halcyon` — clean.
- [x] M7 tests drive the **real compiled `StateGraph`** end-to-end with deterministic `StubToolLLM` nodes (no network) and assert `inter_agent_injection_propagated`, `unauthorized_approval`, and `supervisor_provenance_bypassed` fire/don't-fire correctly across vulnerable and secure runs.

## 3. Live full-stack e2e with a real model (keyless, Ollama) — TO BE FILLED

Stack: `docker compose up -d` against the shared Ollama backend, `HALCYON_MODE` flipped between runs.

- [ ] **Vulnerable** — real `llama3.1:8b`, session drives `/api/dispute` with an injected `dispute_text` targeting `acct-attacker`. Record the response + resulting `/validate/m7`:
  ```
  [vulnerable] decision=<TBD>
  [vulnerable] validate={'core': <TBD>, 'stretch': <TBD>}
  ```
  Expect `core: pass` (injection propagates, unauthorized approval recorded).

- [ ] **Secure** (`HALCYON_MODE=secure`) — the **same** dispute payload, same account/amount:
  ```
  [secure] decision=<TBD>
  [secure] validate={'core': <TBD>, 'stretch': <TBD>}
  ```
  Expect `core: fail` (quarantine + provenance check + `authorize_approval` block the propagation/approval).

- [ ] **The vulnerable→secure diff on an identical dispute payload is the lesson — confirm it's proven live before merging.**

## 4. BYOK-autonomous caveat (expected — same shape as M6)

`llama3.1:8b` (used above for the keyless-floor smoke run, even though M7 is a Day-2/BYOK-tier module per the flag registry) may **not autonomously chain** the injected dispute-text into a full cascading approval the way a stronger tool-calling model will — mirroring the same caveat recorded for M6 (llama won't autonomously chain the poisoned MCP tool description either). If the keyless run above does not reproduce the full core attack autonomously:
- [ ] Confirm whether the mechanism (guard fires correctly for the events it does receive) still checks out via the deterministic suite (§2) — it does, independent of this caveat.
- [ ] Run one **BYOK** confirmation (OpenAI/Anthropic key) to reproduce the fully autonomous cascading-injection attack, consistent with M7 being a Day-2/BYOK module.
- [ ] Record the BYOK result here:
  ```
  [BYOK, provider=<TBD>, model=<TBD>] decision=<TBD>
  [BYOK vulnerable] validate={'core': <TBD>, 'stretch': <TBD>}
  ```

## Deferred (tracked in STATUS.md → Deferred cleanups)

- `_execute_refund` records `unauthorized_approval` for the nonexistent `acct-attacker` target then no-ops the credit (consistent with M5's `tools.py` pattern) — harmless, mechanism-based grading still correct.

## Verdict

**TBD — fill in after the live run.** Per the merge gate: do not merge `s7-m7-multi-agent` until vuln `core:pass` → secure `core:fail` is proven live on the mechanism, matching the M6 bar.
