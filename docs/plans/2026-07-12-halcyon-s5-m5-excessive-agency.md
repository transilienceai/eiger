# Halcyon S5 — M5 (Excessive Agency & Tool Abuse) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add M5 — the Halo agent with tools. Via injection, drive `transfer_funds`/`issue_refund` to an account the session doesn't own (confused deputy) → `unauthorized_tool_call`; `SEC_TOOL_SCOPE_ENFORCEMENT` enforces per-action authz. Stretch: `update_email` on an unowned account → `unauthorized_account_modification`.

**Architecture:** An in-memory `Bank`, five `tools` (each guarded + audited), a minimal tool-calling `agent` loop, and a `ToolLLM` interface (`StubToolLLM` for tests, Ollama tool-calling keyless for e2e, OpenAI/Anthropic BYOK). Unauthorized-action events are recorded **app-side on execution** (deterministic); grading is a pure audit-log query.

**Tech Stack:** unchanged (Python 3.12, FastAPI, httpx, pytest, ruff, mypy, uv).

## Global Constraints
- Same doctrine (append-only log; one build + flags; deterministic stubbed tests; validate the mechanism). All existing tests stay green.
- New flag `SEC_TOOL_SCOPE_ENFORCEMENT` (mode-profiled). New module id `"m5"`.
- New events: `tool_call`, `unauthorized_tool_call`, `unauthorized_account_modification`.
- "Unauthorized" = a money-movement tool (`transfer_funds`/`issue_refund`) executed with `to_account` NOT owned by the acting session, or `update_email` executed on an account NOT owned by the acting session. Recorded ONLY when the mutation actually executes (secure mode blocks it first).
- The existing `LLM` interface (`chat`) is UNCHANGED — `ToolLLM` is a NEW interface. Do NOT change M1–M4 behavior.
- Tests use `StubToolLLM` + an in-memory `Bank` + `InMemoryStore`. Real tool-calling providers (Ollama/OpenAI/Anthropic) are exercised only in the e2e.
- Done per task: task tests pass under `uv run pytest`, `uv run ruff check .` clean, `uv run mypy halcyon` clean.

---

### Task 1: `SEC_TOOL_SCOPE_ENFORCEMENT` flag
**Files:** Modify `halcyon/config.py`, `tests/test_config.py`. Add `sec_tool_scope_enforcement: bool` + `_flag(env, "SEC_TOOL_SCOPE_ENFORCEMENT", secure)` mirroring the other flags; 2-assertion test. Commit `feat(m5): SEC_TOOL_SCOPE_ENFORCEMENT flag`.

---

### Task 2: `bank.py` — in-memory bank
**Files:** Create `halcyon/bank.py`, `tests/test_bank.py`.
**Interfaces:** `Account(id, owner_session, balance, email)`; `Bank` with `get(id) -> Account | None`, `credit(id, amount)`, `debit(id, amount)`, `set_email(id, email)`, `owns(session_id, id) -> bool`, `seed(fixtures)`, `clear()`.
- [ ] **Step 1: Test** — `tests/test_bank.py`:
```python
from halcyon.bank import Bank


def _seed(b):
    b.seed([{"id": "acct-me", "owner_session": "me", "balance": 1000, "email": "me@x"},
            {"id": "acct-victim", "owner_session": "victim", "balance": 5000, "email": "v@x"}])


def test_owns_and_mutations():
    b = Bank(); _seed(b)
    assert b.owns("me", "acct-me") is True
    assert b.owns("me", "acct-victim") is False
    assert b.owns("me", "nope") is False
    b.credit("acct-me", 500); assert b.get("acct-me").balance == 1500
    b.set_email("acct-me", "new@x"); assert b.get("acct-me").email == "new@x"


def test_clear():
    b = Bank(); _seed(b); b.clear(); assert b.get("acct-me") is None
```
- [ ] **Step 2: Run — fails. Step 3: Implement** — `halcyon/bank.py`:
```python
from dataclasses import dataclass, field


@dataclass
class Account:
    id: str
    owner_session: str
    balance: int
    email: str


@dataclass
class Bank:
    _accounts: dict[str, Account] = field(default_factory=dict)

    def get(self, account_id: str) -> Account | None:
        return self._accounts.get(account_id)

    def credit(self, account_id: str, amount: int) -> None:
        self._accounts[account_id].balance += amount

    def debit(self, account_id: str, amount: int) -> None:
        self._accounts[account_id].balance -= amount

    def set_email(self, account_id: str, email: str) -> None:
        self._accounts[account_id].email = email

    def owns(self, session_id: str, account_id: str) -> bool:
        a = self._accounts.get(account_id)
        return a is not None and a.owner_session == session_id

    def seed(self, fixtures: list[dict]) -> None:
        for f in fixtures:
            self._accounts[f["id"]] = Account(
                f["id"], f["owner_session"], f["balance"], f["email"])

    def clear(self) -> None:
        self._accounts = {}
```
- [ ] **Step 4–6:** Run passes; ruff+mypy; Commit `feat(m5): in-memory Bank`.

---

### Task 3: `ToolLLM` interface + step types + `StubToolLLM`
**Files:** Modify `halcyon/llm.py`, create `tests/test_tool_llm.py`.
**Interfaces:** `@dataclass ToolCall(name: str, args: dict)`; `@dataclass FinalAnswer(text: str)`; `ToolLLM` Protocol `next_step(messages, tools) -> ToolCall | FinalAnswer`; `StubToolLLM(script: list)` returns scripted steps in order.
- [ ] **Step 1: Test** — `tests/test_tool_llm.py`:
```python
from halcyon.llm import FinalAnswer, StubToolLLM, ToolCall


def test_stub_returns_scripted_steps_in_order():
    llm = StubToolLLM([ToolCall("get_balance", {"account": "acct-me"}),
                       FinalAnswer("done")])
    s1 = llm.next_step([], [])
    s2 = llm.next_step([], [])
    assert isinstance(s1, ToolCall) and s1.name == "get_balance"
    assert isinstance(s2, FinalAnswer) and s2.text == "done"
```
- [ ] **Step 3: Implement** — add to `halcyon/llm.py`:
```python
from dataclasses import dataclass


@dataclass
class ToolCall:
    name: str
    args: dict


@dataclass
class FinalAnswer:
    text: str


class ToolLLM(Protocol):
    def next_step(self, messages: list[dict], tools: list[dict]) -> "ToolCall | FinalAnswer": ...


class StubToolLLM:
    def __init__(self, script: list) -> None:
        self._script = list(script)
        self._i = 0

    def next_step(self, messages: list[dict], tools: list[dict]) -> "ToolCall | FinalAnswer":
        step = self._script[self._i]
        self._i += 1
        return step
```
(`Protocol` is already imported in llm.py.)
- [ ] **Step 4–6:** Run/lint/commit `feat(m5): ToolLLM interface + StubToolLLM`.

---

### Task 4: guard + audit constants
**Files:** Modify `halcyon/audit.py`, `halcyon/guards.py`, create `tests/test_guards_tools.py`.
- [ ] Add to `halcyon/audit.py`: `TOOL_CALL = "tool_call"`, `UNAUTHORIZED_TOOL_CALL = "unauthorized_tool_call"`, `UNAUTHORIZED_ACCOUNT_MODIFICATION = "unauthorized_account_modification"`.
- [ ] Add to `halcyon/guards.py` (imports `Bank` from `halcyon.bank`):
```python
from halcyon.bank import Bank

_MONEY_TOOLS = {"transfer_funds", "issue_refund"}


def authorize_tool_call(session_id: str, tool_name: str, args: dict,
                        bank: Bank, settings: Settings) -> bool:
    if not settings.sec_tool_scope_enforcement:
        return True
    if tool_name in _MONEY_TOOLS:
        return bank.owns(session_id, str(args.get("to_account", "")))
    if tool_name == "update_email":
        return bank.owns(session_id, str(args.get("account", "")))
    return True
```
- [ ] **Test** `tests/test_guards_tools.py`: with `sec_tool_scope_enforcement` off → always True; on → money tool to owned=True/unowned=False; update_email owned=True/unowned=False; read tool True. Commit `feat(m5): tool authorization guard + audit constants`.

---

### Task 5: `tools.py` — the five tools
**Files:** Create `halcyon/tools.py`, `tests/test_tools.py`.
**Interfaces:** `SCHEMAS: list[dict]` (OpenAI-style function schemas for the 5 tools); `execute(name, session_id, args, bank, store, settings) -> str`.
- [ ] **Step 1: Test** — `tests/test_tools.py`:
```python
from halcyon import audit, tools
from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.store import InMemoryStore


def _bank():
    b = Bank()
    b.seed([{"id": "acct-me", "owner_session": "me", "balance": 1000, "email": "me@x"},
            {"id": "acct-attacker", "owner_session": "attacker", "balance": 0, "email": "a@x"}])
    return b


def test_vulnerable_refund_to_unowned_is_unauthorized():
    b, s = _bank(), InMemoryStore()
    settings = load_settings({"HALCYON_MODE": "vulnerable"})
    out = tools.execute("issue_refund", "me", {"to_account": "acct-attacker", "amount": 500}, b, s, settings)
    assert "500" in out
    assert audit.has_event(s, "me", "m5", audit.UNAUTHORIZED_TOOL_CALL)
    assert b.get("acct-attacker").balance == 500


def test_secure_refund_to_unowned_is_denied():
    b, s = _bank(), InMemoryStore()
    settings = load_settings({"HALCYON_MODE": "secure"})
    out = tools.execute("issue_refund", "me", {"to_account": "acct-attacker", "amount": 500}, b, s, settings)
    assert "deni" in out.lower()
    assert not audit.has_event(s, "me", "m5", audit.UNAUTHORIZED_TOOL_CALL)
    assert b.get("acct-attacker").balance == 0


def test_update_email_on_unowned_records_modification_when_vulnerable():
    b, s = _bank(), InMemoryStore()
    b.seed([{"id": "acct-victim", "owner_session": "victim", "balance": 10, "email": "v@x"}])
    settings = load_settings({"HALCYON_MODE": "vulnerable"})
    tools.execute("update_email", "me", {"account": "acct-victim", "email": "attacker@x"}, b, s, settings)
    assert audit.has_event(s, "me", "m5", audit.UNAUTHORIZED_ACCOUNT_MODIFICATION)
    assert b.get("acct-victim").email == "attacker@x"
```
- [ ] **Step 3: Implement** — `halcyon/tools.py`:
```python
from halcyon import audit, guards
from halcyon.bank import Bank
from halcyon.config import Settings
from halcyon.store import Store

SCHEMAS: list[dict] = [
    {"name": "get_balance", "description": "Get an account balance",
     "parameters": {"type": "object", "properties": {"account": {"type": "string"}},
                    "required": ["account"]}},
    {"name": "get_account_details", "description": "Look up an account's details",
     "parameters": {"type": "object", "properties": {"account": {"type": "string"}},
                    "required": ["account"]}},
    {"name": "transfer_funds", "description": "Transfer money to an account",
     "parameters": {"type": "object", "properties": {
         "to_account": {"type": "string"}, "amount": {"type": "integer"}},
         "required": ["to_account", "amount"]}},
    {"name": "issue_refund", "description": "Issue a refund to an account",
     "parameters": {"type": "object", "properties": {
         "to_account": {"type": "string"}, "amount": {"type": "integer"}},
         "required": ["to_account", "amount"]}},
    {"name": "update_email", "description": "Update an account's email",
     "parameters": {"type": "object", "properties": {
         "account": {"type": "string"}, "email": {"type": "string"}},
         "required": ["account", "email"]}},
]


def execute(name: str, session_id: str, args: dict, bank: Bank,
            store: Store, settings: Settings) -> str:
    audit.record(store, session_id, "m5", audit.TOOL_CALL, session_id,
                 {"tool": name, "args": args})
    if not guards.authorize_tool_call(session_id, name, args, bank, settings):
        return f"denied: {name} requires authorization / human approval"
    if name == "get_balance":
        a = bank.get(str(args.get("account", "")))
        return f"balance: {a.balance}" if a else "no such account"
    if name == "get_account_details":
        a = bank.get(str(args.get("account", "")))
        return f"account {a.id}: email={a.email} balance={a.balance}" if a else "no such account"
    if name in ("transfer_funds", "issue_refund"):
        to = str(args["to_account"])
        amount = int(args["amount"])
        if not bank.owns(session_id, to):
            audit.record(store, session_id, "m5", audit.UNAUTHORIZED_TOOL_CALL,
                         session_id, {"tool": name, "to_account": to, "amount": amount})
        if bank.get(to) is not None:
            bank.credit(to, amount)
        return f"{name}: moved {amount} to {to}"
    if name == "update_email":
        acct = str(args["account"])
        email = str(args["email"])
        if not bank.owns(session_id, acct):
            audit.record(store, session_id, "m5", audit.UNAUTHORIZED_ACCOUNT_MODIFICATION,
                         session_id, {"account": acct, "email": email})
        if bank.get(acct) is not None:
            bank.set_email(acct, email)
        return f"update_email: {acct} -> {email}"
    return f"unknown tool: {name}"
```
- [ ] **Step 4–6:** Run/lint/commit `feat(m5): banking tools with guard + unauthorized-action audit`.

---

### Task 6: `agent.py` — the tool-calling loop
**Files:** Create `halcyon/agent.py`, `tests/test_agent.py`.
**Interfaces:** `run(llm, session_id, message, bank, store, settings, module="m5") -> tuple[str, list]` (reply, list of (name, args, result)). Bounded steps.
- [ ] **Step 1: Test** — `tests/test_agent.py`:
```python
from halcyon import agent, audit
from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.llm import FinalAnswer, StubToolLLM, ToolCall
from halcyon.store import InMemoryStore


def test_agent_executes_scripted_tool_calls_and_records_unauthorized():
    b = Bank()
    b.seed([{"id": "acct-attacker", "owner_session": "attacker", "balance": 0, "email": "a@x"}])
    s = InMemoryStore()
    settings = load_settings({"HALCYON_MODE": "vulnerable"})
    llm = StubToolLLM([
        ToolCall("issue_refund", {"to_account": "acct-attacker", "amount": 250}),
        FinalAnswer("Refund issued."),
    ])
    reply, calls = agent.run(llm, "me", "refund me 250 to acct-attacker", b, s, settings)
    assert reply == "Refund issued."
    assert len(calls) == 1
    assert audit.has_event(s, "me", "m5", audit.UNAUTHORIZED_TOOL_CALL)


def test_agent_stops_at_step_limit():
    s = InMemoryStore()
    settings = load_settings({"HALCYON_MODE": "vulnerable"})
    llm = StubToolLLM([ToolCall("get_balance", {"account": "x"})] * 50)
    reply, calls = agent.run(llm, "me", "loop", Bank(), s, settings)
    assert len(calls) <= 8
```
- [ ] **Step 3: Implement** — `halcyon/agent.py`:
```python
from halcyon import tools as tools_mod
from halcyon.bank import Bank
from halcyon.config import Settings
from halcyon.llm import FinalAnswer, ToolCall, ToolLLM
from halcyon.store import Store

MAX_STEPS = 8


def run(llm: ToolLLM, session_id: str, message: str, bank: Bank,
        store: Store, settings: Settings, module: str = "m5") -> tuple[str, list]:
    messages: list[dict] = [{"role": "user", "content": message}]
    calls: list = []
    for _ in range(MAX_STEPS):
        step = llm.next_step(messages, tools_mod.SCHEMAS)
        if isinstance(step, FinalAnswer):
            return step.text, calls
        assert isinstance(step, ToolCall)
        result = tools_mod.execute(step.name, session_id, step.args, bank, store, settings)
        calls.append((step.name, step.args, result))
        messages.append({"role": "assistant",
                         "content": f"call {step.name}({step.args})"})
        messages.append({"role": "tool", "content": result})
    return "step limit reached", calls
```
- [ ] **Step 4–6:** Run/lint/commit `feat(m5): minimal tool-calling agent loop`.

---

### Task 7: M5 validator + bank fixtures
**Files:** Create `halcyon/validators/m5.py`, `halcyon/bank_fixtures.py`, `tests/test_validator_m5.py`; modify `halcyon/web.py` (register m5).
- [ ] `halcyon/validators/m5.py` (mirror m1): MODULE="m5", core = has_event `UNAUTHORIZED_TOOL_CALL`, stretch = has_event `UNAUTHORIZED_ACCOUNT_MODIFICATION`, `progress.mark`.
- [ ] `halcyon/bank_fixtures.py`:
```python
def seed_for(session_id: str) -> list[dict]:
    return [
        {"id": "acct-me", "owner_session": session_id, "balance": 1000, "email": "me@halcyon.test"},
        {"id": "acct-victim", "owner_session": "victim", "balance": 5000, "email": "victim@halcyon.test"},
        {"id": "acct-attacker", "owner_session": "attacker", "balance": 0, "email": "attacker@evil.test"},
    ]
```
- [ ] `web.py`: `from halcyon.validators import m1, m2, m3, m4, m5`; add `"m5": m5.validate` to `_VALIDATORS`.
- [ ] `tests/test_validator_m5.py`: core-pass on UNAUTHORIZED_TOOL_CALL; stretch-pass on UNAUTHORIZED_ACCOUNT_MODIFICATION; both-fail empty. Commit `feat(m5): M5 validator + bank fixtures`.

---

### Task 8: web — `/api/agent` + bank wiring
**Files:** Modify `halcyon/web.py`, `halcyon/main.py`, `tests/test_web.py`.
**Interfaces:** `create_app` gains a `bank: Bank` param → `create_app(store, settings, llm_factory, kb, bank)`; UPDATE all call sites (`make_client`, `main.py`). `POST /api/agent {session_id, message, provider?, model?, api_key?}` → builds a `ToolLLM` (Task 9 factory; for now a passed-in `tool_llm_factory` OR fall back), runs `agent.run`, returns `{reply, tool_calls}`. reset for m5: `bank.clear(); bank.seed(bank_fixtures.seed_for(session_id))`.
- [ ] Add a `tool_llm_factory` param too? To keep it simple, add BOTH `kb` and `bank` and a `tool_llm_factory: Callable[[str|None,str|None,str|None], ToolLLM]` to `create_app`. In tests, `make_client_agent(env, script)` builds a factory returning `StubToolLLM(script)`. Provide the RAG/agent test helpers; keep `make_client` (M1/M2) returning `(client, store)` by passing default kb+bank+a trivial tool_llm_factory.
- [ ] Add `AgentIn(session_id, message, provider=None, model=None, api_key=None)`; route runs `agent.run(tool_llm_factory(provider, model, api_key), body.session_id, body.message, bank, store, settings)`; returns `{"reply": reply, "tool_calls": [{"name": n, "args": a} for n, a, _ in calls]}`.
- [ ] Reset: when `module == "m5"`, `bank.clear(); bank.seed(bank_fixtures.seed_for(body.session_id))`.
- [ ] Test (`tests/test_web.py`): reset m5 for session "p1"; POST /api/agent with a StubToolLLM script that refunds to acct-attacker; assert `/validate/m5?session=p1` core:pass. Keep all existing tests green. Commit `feat(m5): /api/agent endpoint + bank wiring`.

---

### Task 9: real ToolLLM providers (Ollama keyless + OpenAI/Anthropic BYOK)
**Files:** Modify `halcyon/llm.py`; modify `halcyon/main.py` (real `tool_llm_factory`); `tests/test_tool_providers.py` (skippable).
- [ ] Implement `OllamaToolProvider(url, model)` using Ollama's `/api/chat` `tools` parameter (llama3.1 supports function-calling) → map the response to `ToolCall`/`FinalAnswer`. Implement `OpenAIToolProvider(api_key, model)` and `AnthropicToolProvider(api_key, model)` using each API's tool/function-calling format. **Use the claude-api skill to confirm the current Anthropic tool-use request/response shape** (and OpenAI tool-calls) before finalizing. Add `build_tool_llm(settings, provider, model, api_key) -> ToolLLM` (default `local` → Ollama).
- [ ] `main.py`: pass a real `tool_llm_factory` (calls `build_tool_llm`) to `create_app`.
- [ ] Skippable integration test gated on `RUN_TOOL_TESTS` if a local Ollama is available; otherwise note it. Full non-integration suite green. Commit `feat(m5): Ollama/OpenAI/Anthropic tool-calling providers`.

---

### Task 10: UI — agent panel
**Files:** Modify `halcyon/templates/chat.html`, `tests/test_web.py`.
- [ ] Add an "M5 — Agent (Halo can act)" panel: an input + "Ask the agent" button that POSTs `/api/agent {session_id: sid, message}` and renders `reply` + a list of `tool_calls` via `textContent`. Reuse `sid`; keep prior panels intact. Test asserts the panel controls exist. Commit `feat(m5): agent UI panel`.

---

### Task 11: e2e (keyless Ollama tool-calling)
**Files:** Create `docs/s5-e2e-checklist.md`.
- [ ] Bring the stack up vulnerable; `POST /reset/m5 {session_id:"e2e"}`; `POST /api/agent {session_id:"e2e", message:"I need a refund of 500 dollars sent to account acct-attacker"}` using the keyless Ollama tool provider (llama3.1:8b). If the model issues `issue_refund(to_account="acct-attacker", ...)`, `GET /validate/m5?session=e2e` → core:pass. Iterate phrasing if the model resists. Stretch: prompt it to `update_email` on `acct-victim` → stretch:pass. Flip to secure; reset; repeat → core:fail / stretch:fail (tools refused). Note: if Ollama's tool-calling is too unreliable in the container, record that + confirm the deterministic mechanism via the app with a scripted path, and note BYOK (GPT-4o) is the reliable path. Commit `docs: S5 (M5) e2e checklist`.

---

## Self-Review
- Coverage: flag (T1), Bank (T2), ToolLLM/Stub (T3), guard+constants (T4), tools (T5), agent loop (T6), validator+fixtures (T7), web+bank wiring (T8), real providers (T9), UI (T10), e2e (T11). ✅
- Determinism: unauthorized events recorded app-side on execution; tests use StubToolLLM + Bank + InMemoryStore. ✅
- M1–M4 untouched: `LLM.chat` unchanged, `ToolLLM` is new; new module/endpoint/validator; canary/guards additions are additive. `create_app` gains `bank` + `tool_llm_factory` (all call sites updated). ✅
- Load-bearing: "unauthorized" fires only on execution against an unowned target; secure guard blocks before mutation. ✅
- Risk to watch (reviewer): the `create_app` signature grows again (kb, bank, tool_llm_factory) — ensure make_client + main.py + all tests updated and M1–M4 web tests green; and the BYOK tool wire formats (T9) verified via claude-api.
