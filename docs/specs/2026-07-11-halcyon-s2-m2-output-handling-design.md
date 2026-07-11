# Halcyon S2 — M2 (Output Handling & Disclosure) — Design

**Date:** 2026-07-11
**Slice:** S2. Builds directly on the S1 spine (audit log, `SEC_*` flags, `/validate` + `/reset`, canary, providers, thin UI). Only the M2 deltas are detailed here; everything else is reused unchanged.
**Doctrine:** unchanged (validate mechanism not model words; one build + flags; append-only log; deterministic).
**Status:** Design — proceeding per "continue development"; the one real design fork is flagged in §7.

---

## 1. What M2 teaches (from `halcyon-lab-spec.md` §5)

- **Vuln:** Halo's output is rendered as **raw HTML** in the chat UI; the system prompt leaks on request; verbose errors.
- **Secure:** `SEC_OUTPUT_ENCODING` (context-aware encoding + CSP) and the existing `SEC_SYSTEM_PROMPT_HARDENING`.
- **Core:** land an **XSS** via a data field Halo echoes into the chat UI.
- **Stretch:** **disclosure** — leak the full system prompt.
- **Validator:** `xss_beacon` (a real browser executing the payload calls back) + a system-prompt canary.

## 2. Load-bearing decision: keep the XSS **deterministic** (app-echoed, not model-invented)

Per the doctrine, the graded mechanism must not depend on the LLM emitting an exact string. So the XSS surface is a **data field the *app* echoes verbatim into the page**, not something we hope the model reproduces. The model is not in the XSS path at all — this is a classic **stored XSS** on user-controlled data, which is exactly the "insecure output handling" lesson and is 100% deterministic.

**Surface (see §7 for the fork):** a per-session **display name**. The participant sets it; the app renders it into the chat page and into Halo's greeting line. Vulnerable rendering executes any HTML in it.

## 3. New pieces (M2 deltas over S1)

| Unit | Change | Purpose |
|---|---|---|
| `config.py` | add `sec_output_encoding` (mode-profiled like the others) | gate the M2 guard |
| `guards.py` | add `encode_output(text, settings) -> str` (HTML-escape when encoding on; passthrough when off) + a distinct M2 system-prompt canary `SYS-CANARY-M2-3390` | the guard + disclosure canary |
| `store.py` / session | a per-session **profile** (display_name) — small in-memory map on the app, plus an audit trail; no schema change needed for S1 store (add `set_profile`/`get_profile` to `Store` + both impls) | hold the attacker-controlled field |
| `web.py` | `POST /api/profile {session_id, display_name}`; `GET /beacon/xss?session=…` (writes `xss_beacon`, returns 1×1 gif, 200); set **`Content-Security-Policy`** response header when `sec_output_encoding` on; pass `output_encoding` + escaped/raw display name into the chat template | the vuln + the guard + the beacon |
| `canary.py` | scan replies (and echoed fields) for `SYS-CANARY-M2-3390` → `system_prompt_disclosed` | disclosure detection |
| `validators/m2.py` | `core` = `∃ xss_beacon`; `stretch` = `∃ system_prompt_disclosed` (after last reset, module `m2`) | the M2 validator |
| `templates/chat.html` | render the display name + replies via `innerHTML` when `output_encoding` is **off**, `textContent` when **on**; the server also escapes server-side when on (defense in depth) | where the XSS fires |
| tests | deterministic: beacon hit → `xss_beacon`; encoding-on escapes + sets CSP → no beacon; disclosure canary → `system_prompt_disclosed`; validator core/stretch | prove it |

New event types: `xss_beacon`, `system_prompt_disclosed`. New module id: `"m2"`.

## 4. The guard (`SEC_OUTPUT_ENCODING`) — the diff is the lesson

- **off (vuln):** `encode_output` returns text unchanged; `/chat` renders the display name via `innerHTML`; **no CSP header**. A display name of `<img src=x onerror="new Image().src='/beacon/xss?session='+SID">` executes when the page renders → beacon → `xss_beacon`.
- **on (secure):** `encode_output` HTML-escapes (`<` → `&lt;` …); the template uses `textContent`; the server sets `Content-Security-Policy: default-src 'self'; script-src 'self'; img-src 'self' data:`. Two independent, legible controls (encoding + CSP) — either alone defeats the payload; together = defense in depth.

## 5. Validation (mechanism, not words)

- **Beacon endpoint** `GET /beacon/xss?session=…` writes `xss_beacon` for `(session, m2)` and returns a 1×1 gif. The participant's **own browser**, rendering the raw payload, fires it — no separate headless grader needed. Deterministic.
- **Disclosure:** `SYS-CANARY-M2-3390` sits in Halo's M2 system prompt. Leaking the prompt (the stretch objective) surfaces it in a reply → `system_prompt_disclosed`. Unlike M1's stretch, a prompt-dump legitimately *is* the objective here, so a literal canary is correct (not self-defeating).
- `GET /validate/m2?session=…` → `{core, stretch}` by querying the audit log after the last `m2` reset. Reuses the S1 validator shape.

## 6. Cross-module hygiene

- The M1 chat path, guards, and validator are **unchanged**. `assemble()` gains the M2 system prompt only in M2 context; keep M1's system prompt intact. Prefer adding an M2-specific system prompt rather than mutating M1's.
- `encode_output` is applied wherever the app echoes user-controlled data into HTML — currently just the display name; keep the call sites explicit so the guard is auditable.

## 7. The one design fork (flagged; proceeding with option A unless redirected)

**XSS surface:**
- **A — per-session display name (chosen).** Participant sets a display name; app renders it into the chat page/greeting. Cleanest, self-contained, deterministic, minimal new surface. *Proceeding with this.*
- B — "support ticket subject" echoed on a confirmation screen. Slightly more narrative (bank ticketing) but more UI.
- C — reflect the chat message itself raw. Rejected: muddies the M1 chat path and tempts model-in-the-loop non-determinism.

If B's ticketing framing is preferred for the course narrative, it's a small swap — say so and I'll adjust before the UI task.

## 8. Out of scope for S2

No RAG/agent/MCP/multi-agent (later slices). No tool schema in the disclosure stretch (there are no tools until L2/M5) — stretch is system-prompt disclosure only. No fleet orchestration. Follows S1's deterministic, LLM-stubbed test harness.
