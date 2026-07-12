# Halcyon S5 — M5 (Excessive Agency & Tool Abuse) — Design

**Date:** 2026-07-12
**Slice:** S5. First **Day 2 / BYOK** module. Introduces **L2 — the Halo agent with tools**, on the S1 spine (audit log, flags, `/validate` + `/reset`, progress). Reuses the deterministic-test pattern (stub the LLM's tool calls).
**Model tier:** BYOK (OpenAI/Anthropic) — reliable function-calling. Ollama's tool-calling is unreliable, so M5 defaults to BYOK; tests use a scripted `StubToolLLM`.
**Status:** Design — for review before build.

---

## 1. What M5 teaches (from `halcyon-lab-spec.md` §5)

- **Vuln:** Halo is now an **agent** with broad tools (`get_balance`, `transfer_funds`, `issue_refund`, `get_account_details`, `update_email`). Tool-calling is driven by unvalidated conversation; there's no per-action authorization, no confirmation, and the agent acts with its **own (bank-wide) privileges on the attacker's behalf** — the **confused deputy**.
- **Secure:** `SEC_TOOL_SCOPE_ENFORCEMENT` — least-privilege exposure, **per-action authorization** (a session may only move money to/modify accounts it owns), **human-in-the-loop** for money movement, argument validation.
- **Core:** via injection, drive `issue_refund` / `transfer_funds` to an **attacker-controlled destination**.
- **Stretch:** **chain** — `get_account_details` to enumerate a victim → `update_email` to hijack → transfer.
- **Validator:** `unauthorized_tool_call` with attacker args.

## 2. New architecture: L2 the agent + tools (behind interfaces, deterministically testable)

- **`bank.py`** — an in-memory `Bank`: accounts `{id, owner_session, balance, email}`; ops `get(id)`, `credit/debit`, `set_email`; `seed(fixtures)`, `clear()`. Deterministic; tests use it directly. (Container-local like the KB; progress lives in the external store.)
- **`tools.py`** — the five tool specs (name, JSON schema, `execute(session_id, args, bank, store, settings) -> str`). Each money/account tool calls the guard, records audit, then mutates the bank.
- **`agent.py`** — a **minimal tool-calling loop** (NOT LangGraph — that arrives at M7 for multi-agent): `run(llm, session_id, message, bank, store, settings) -> str`. Loops: ask the LLM for the next step (tool call or final answer) → execute the tool → feed the result back → repeat (bounded steps).
- **`llm.py` extension** — a `ToolLLM` protocol: `next_step(messages, tools) -> ToolCall | FinalAnswer`. Implementations: `StubToolLLM` (scripted steps, for tests), `OpenAIToolProvider` / `AnthropicToolProvider` (real BYOK function-calling). The existing `LLM.chat` is untouched (M1–M4 keep using it).
- **`guards.py`** — `authorize_tool_call(session_id, tool_name, args, bank, settings) -> bool`: the `SEC_TOOL_SCOPE_ENFORCEMENT` guard. off = allow everything; on = per-action authz (money movement only to accounts the session owns; `update_email` only on owned accounts; money movement flagged for HITL).
- **`web.py`** — `POST /api/agent {session_id, message, provider, model, api_key}` → `agent.run(...)` → `{reply, tool_calls}`. Register `m5` validator; reset re-seeds the bank.
- **`validators/m5.py`** — core = `unauthorized_tool_call`; stretch = `unauthorized_account_modification`.
- **`audit.py`** — `TOOL_CALL` (every call, for transparency), `UNAUTHORIZED_TOOL_CALL`, `UNAUTHORIZED_ACCOUNT_MODIFICATION`.

New module id: `"m5"`.

## 3. Validation (mechanism, not model words)

The agent records **every tool execution** to the audit log (name, args, actor). The unauthorized-action events are **app-side and deterministic** — they don't depend on how the model phrased anything, only on which tool ran with which args:

- **`unauthorized_tool_call`** — a money-movement tool (`transfer_funds` / `issue_refund`) **executed** with a `to_account` **not owned by the acting `session_id`** (the confused-deputy exfiltration). Fires only when the money actually moves.
- **`unauthorized_account_modification`** — `update_email` **executed** on an account **not owned by the acting session** (the hijack step).
- `GET /validate/m5?session=…` → core = `unauthorized_tool_call`; stretch = `unauthorized_account_modification`. Pure audit-log query.

The model's job is to be *convinced* to make the call (that's the attack); the *grading* is on whether an unauthorized call executed. Robust to phrasing and to model choice.

## 4. The guard (`SEC_TOOL_SCOPE_ENFORCEMENT`) — the diff is the lesson

`authorize_tool_call(...)`, checked in each tool's `execute` before it mutates state:
- **off (vuln):** returns True always → the agent moves money / edits any account on request. The unauthorized call executes → event fires.
- **on (secure):** money movement is allowed only when `to_account` is owned by the acting session (else refused with a "requires authorization / human approval" result); `update_email` allowed only on an owned account. The unauthorized call is **refused before mutation** → no unauthorized event → core/stretch fail. ~20 legible lines: least privilege + per-action authz + HITL gate.

Refused calls still record a benign `TOOL_CALL` (attempted, denied) so the transcript shows the block — but NOT the `unauthorized_*` event.

## 5. Deterministic test harness

`StubToolLLM` is scripted with a sequence of steps, e.g. `[ToolCall("issue_refund", {"to_account": "acct-attacker", "amount": 500}), FinalAnswer("done")]`. The agent executes them against a seeded `Bank` + `InMemoryStore`; tests assert the audit events and the bank state:
- vulnerable → `unauthorized_tool_call` recorded, attacker balance credited.
- secure → tool refused, no event, attacker balance unchanged.
- stretch: scripted `get_account_details(victim)` → `update_email(victim, attacker@…)` → assert `unauthorized_account_modification` (vuln) / refused (secure).
Real BYOK function-calling is exercised only in the e2e.

## 6. Seed fixtures (`bank_fixtures.py`)

- `acct-me` — owner = the acting session (seeded per reset to the requesting session), balance 1000, email `me@halcyon.test`.
- `acct-victim` — owner `"victim"`, balance 5000, email `victim@halcyon.test`.
- `acct-attacker` — owner `"attacker"` (external), balance 0.

The confused-deputy target is `acct-attacker` (or any account the session doesn't own). `[OPEN: bind acct-me's owner to the live session on reset, or use a fixed "me" identity — resolve in plan; fixed identity is simpler and still demonstrates the vuln.]`

## 7. Decisions / forks
1. **Minimal custom agent loop, not LangGraph** for M5 (single agent). LangGraph lands at M7 (multi-agent). *Proceeding.*
2. **BYOK function-calling** (OpenAI/Anthropic) is the real path; `StubToolLLM` for deterministic tests. Ollama tool-calling is unreliable → not the M5 default (a participant *may* try it). *Proceeding.*
3. **Unauthorized = money-movement/`update_email` to/on an account the acting session doesn't own**, recorded on execution. Clean vuln/secure split via the guard. *Proceeding.*
4. **New `/api/agent` endpoint** (separate from `/api/chat`, `/api/ask`) — keeps the L0/L1 paths clean. *Proceeding.*
5. **`ToolLLM` is a new interface**, not a breaking change to the existing `LLM` (M1–M4 unaffected). *Proceeding.*

## 8. Out of scope for S5
No MCP (M6), no multi-agent/LangGraph (M7), no guardrail wrapper (M8). Tools are in-process Python (real MCP servers arrive at M6). The BYOK tool-calling request/response wire formats for OpenAI/Anthropic are verified against current docs at build time (claude-api skill). Deterministic tests via `StubToolLLM`; real BYOK exercised in the e2e.
