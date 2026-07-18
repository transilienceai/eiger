# S6 / M6 (MCP Security) — Live e2e sign-off

**Date:** 2026-07-18 · **Branch:** `s6-m6-mcp-security` · **Suite:** 136 passed, 4 skipped · ruff + mypy clean.

M6 puts two **real MCP SDK servers** (`mcp-core-banking`, `mcp-crm`) behind the Halo agent. Grading is host-side against the append-only audit log (mechanism, not model words), so it is identical on the SDK in-memory transport (tests) and real streamable-HTTP (deploy).

## What was proven

### 1. Deterministic + gated-HTTP (both transports, no model dependence)
- `136 passed, 4 skipped` — the M6 unit/integration tests drive real MCP client↔server sessions over the **in-memory transport** and assert the audit events fire (poisoning, rug pull, token theft) in vulnerable mode and are blocked in secure mode.
- **Gated real-HTTP e2e** (`RUN_MCP_HTTP_TESTS=1 uv run pytest tests/test_mcp_http.py`) — **2 passed**: over real streamable-HTTP MCP servers, a scripted agent run fires `mcp_poisoned_invocation` (poisoning) and `token_read` (token theft). Proves the guards + attribution survive the wire, not just the in-memory path.

### 2. Live full-stack e2e with a real model
Stack: `docker compose up -d` → 5 services (`web`, `db`, `ollama`, `mcp-core-banking`, `mcp-crm`) on the internal network; `web` speaks real streamable-HTTP to the two MCP containers.

`/health` → `{"status":"ok","mode":"vulnerable","ollama":"up","db":"up","mcp":"up"}` — the new `mcp` probe confirms both MCP servers reachable over HTTP.

**Vulnerable** — real `llama3.1:8b` over real HTTP MCP, session drives `/api/mcp-agent` → the model calls `core_banking__get_account_details`; the poisoned `crm__get_customer` description was served (`_served_poison`), so the sensitive call is graded:
```
[vulnerable] tool_calls=['core_banking__get_account_details']
[vulnerable] validate={'core': 'pass', 'stretch': 'pass'}
```

**Secure** (`HALCYON_MODE=secure docker compose up -d`) — the **same** sensitive call, but `SEC_MCP_DESC_PINNING` quarantines the poisoned description so `_served_poison` stays false:
```
[secure] tool_calls=['core_banking__get_account_details']
[secure] validate={'core': 'fail', 'stretch': 'fail'}
```

**The vulnerable→secure diff on an identical model action is the lesson, proven live.**

## Known caveat (expected — M6 is a BYOK module)
`llama3.1:8b` (the keyless Day-1 floor) will **not autonomously chain** the poisoned tool-description instruction — across 4 prompt variants it called only `crm__get_customer` and stopped. The autonomous poison-following attack (model reads the hidden instruction in the tool description and *chooses* to make the extra cross-server call) reproduces with **BYOK** (GPT-4o / Claude), which is M6's intended tier (Day-2 needs the participant's key for function-calling reliability). The grading mechanism itself is fully proven above; only the *autonomous* trigger needs the stronger model. → **Run one BYOK confirmation when a key is available** (consistent with the standing Day-2 BYOK-smoke-test deferral).

## Deferred (tracked in STATUS.md → Deferred cleanups)
- Rug-pull "benign-at-approval" counter is process-global — on a *shared* `mcp-crm` it permanently mutates after the first `list_tools`; `/reset/m6` doesn't reset it. Grading stays correct both modes; only the demo narrative degrades on a shared container. Resolved by per-participant MCP isolation (Ops slice).
- `mcp_poisoned_invocation` attribution is deliberately coarse (any served poison arms the next sensitive core call).
- web container `uv run` CMD re-syncs dev deps at startup (~40s first boot) — trim in the Ops slice.

## Verdict
**M6 core + stretch grading proven correct in both directions, on both transports, with a real model. Ready to merge.**
