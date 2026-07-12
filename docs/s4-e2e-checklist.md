# S4 (M4) End-to-End Verification Checklist + Sign-off

**Date:** 2026-07-12
**Branch:** `s4-m4-supply-chain`
**Operator:** automated manual-e2e run (Task 8)
**Module:** M4 — supply-chain audit (poisoned pickle artifact + vulnerable pinned dependency). **No LLM in this module** — no model pull needed, `HALCYON_MODE` only gates the artifact loader.

This artifact proves the S4/M4 spine end-to-end: **static scan identifies the poisoned artifact by sha256 → participant submits the finding → server-side check against the known-bad answer records the audit event → `/validate/m4` reports `core:pass` off that audit-log query (never off model output — M4 has no model in the loop at all) → the same for the stretch (vulnerable dependency pin) → an incorrect submission is not credited.**

---

## Step 1 — Static scanner (no app needed)

Command:
```
uv run python -m halcyon.scan_artifact labs/m4/artifacts/community_model.pkl labs/m4/artifacts/embedding_model.safetensors
```

Actual output:
```
labs/m4/artifacts/community_model.pkl  sha256=22e1a204f515884ef978482e768a3022b7681a9813e109c84f7862fec5971b66  MALICIOUS
    ! STACK_GLOBAL -> posix system
    ! REDUCE (callable invocation)
labs/m4/artifacts/embedding_model.safetensors  sha256=67df03f74e575a24fffa17c19f5c7fbe38c54f514adb72fc2a05f16e8ea469e9  MALICIOUS
    ! parse error: no newline found when trying to read stringnl
```

**Poisoned artifact:** `community_model.pkl`, **sha256 = `22e1a204f515884ef978482e768a3022b7681a9813e109c84f7862fec5971b66`**. The scanner correctly flags it via `STACK_GLOBAL -> posix system` (the `os.system` global being resolved) and `REDUCE` (the callable invocation that would fire `os.system(...)` on unpickle) — this matches `labs/m4/build_poisoned.py`, which pickles a `__reduce__` returning `(os.system, ("echo halcyon-m4-rce",))`.

### Known issue — `embedding_model.safetensors` is also flagged `MALICIOUS` (expected: clean)

Per the task brief and `docs/specs/2026-07-12-halcyon-s4-m4-supply-chain-design.md` (§6 test line: *"scanner flags the poisoned pickle and clears the benign ones"*), the benign `.safetensors` fixture should scan as `clean`. It does not. Root cause, confirmed by reading `halcyon/scan_artifact.py`:

```python
try:
    for opcode, arg, _pos in pickletools.genops(data):
        ...
except Exception as exc:  # noqa: BLE001 - malformed pickle is itself suspicious
    dangerous.append(f"parse error: {exc}")
```

`scan()` unconditionally runs `pickletools.genops` on **every** file regardless of format. `labs/m4/artifacts/embedding_model.safetensors` is a 28-byte placeholder (`b"SAFE_PLACEHOLDER_TENSOR_DATA"`, per the S4 plan doc, not a real safetensors binary and not a pickle stream at all). Feeding non-pickle bytes to `pickletools.genops` raises `ValueError: no newline found when trying to read stringnl`, and the bare `except Exception` treats *any* parse failure as equivalent to a dangerous opcode, so it gets labeled `MALICIOUS` for the wrong reason (unparseable ≠ malicious).

This does **not** block the app-level grading path (Steps 2–3 below) — `/submit/m4` checks the submitted hash against a fixed known-bad answer in `halcyon/m4_answers.py`, not against `scan_artifact.py`'s verdict — but it does mean the standalone scanner tool, as shipped, cannot be used by participants to distinguish "poisoned" from "benign" by verdict label alone (a participant would see both files marked `MALICIOUS`). The **reasons** printed still differ meaningfully (`STACK_GLOBAL`/`REDUCE` = real dangerous opcodes vs. `parse error` = scan failure), so a careful participant can still tell them apart, but the top-line verdict is misleading and contradicts the lab's own design intent. No test in `tests/test_scan_artifact.py` or `tests/test_m4_answers.py` currently exercises scanning a non-pickle file, so this gap wasn't caught by the existing suite.

**Flagging for follow-up; not fixed in this task** (scope here is verification + docs, not code changes).

---

## Step 2 — App submit → validate flow (vulnerable mode)

Command: `HALCYON_MODE=vulnerable docker compose up -d --build`

`GET /health` (polled every 5s; ready on the 10th poll — no model pull delay since M4 has no LLM, but the web container still does the one-time ChromaDB `all-MiniLM-L6-v2` embedding-model download on first startup for the KB seed used by other modules):
```json
{"status":"ok","mode":"vulnerable","ollama":"up","db":"up"}
```

**Core — correct malicious-artifact submission:**

`POST /submit/m4`
```json
{"session_id":"e2e","finding_type":"malicious_artifact","value":"22e1a204f515884ef978482e768a3022b7681a9813e109c84f7862fec5971b66"}
```
→ `{"correct":true}`

`GET /validate/m4?session=e2e` → `{"core":"pass","stretch":"fail"}`

**Stretch — correct vulnerable-dependency submission:**

`labs/m4/requirements-vulnerable.txt` pins `PyYAML==5.3.1` (a known-CVE version).

`POST /submit/m4`
```json
{"session_id":"e2e","finding_type":"vulnerable_dependency","value":"PyYAML==5.3.1"}
```
→ `{"correct":true}`

`GET /validate/m4?session=e2e` → `{"core":"pass","stretch":"pass"}`

**Wrong submission is not credited:**

`POST /submit/m4`
```json
{"session_id":"e2e","finding_type":"malicious_artifact","value":"deadbeef"}
```
→ `{"correct":false}`

`GET /validate/m4?session=e2e` (unchanged, re-checked after the wrong submission) → `{"core":"pass","stretch":"pass"}` — confirms a wrong value neither flips an already-passing check nor gets silently credited.

**Bonus — `/reset/m4` verified:**

`POST /reset/m4 {"session_id":"e2e"}` → `{"status":"reset","module":"m4"}`; immediate `GET /validate/m4?session=e2e` → `{"core":"fail","stretch":"fail"}`. Re-submitted both correct findings afterward to restore `core:pass, stretch:pass` for the record below.

---

## Step 3 — Tear down

`docker compose down` (volumes `eiger_pgdata` / `eiger_ollama` kept).

Full targeted test suite also re-run locally (outside the container) as a sanity check:
```
$ uv run pytest tests/ -k "m4 or artifact or scan" -q
...............                                                          [100%]
15 passed, 73 deselected, 1 warning in 0.31s
```
None of the 15 passing tests cover the safetensors-misclassification gap above — consistent with the finding that it's an untested code path.

---

## Result

| Check | Result |
|---|---|
| Scanner flags poisoned `.pkl` as `MALICIOUS` with correct sha256 + real dangerous-opcode reasons | **pass** |
| Scanner rates benign `.safetensors` as `clean` | **fail — known issue, see Step 1** |
| `/submit/m4` correct `malicious_artifact` → `{"correct":true}` → `core:pass` | **pass** |
| `/submit/m4` correct `vulnerable_dependency` → `{"correct":true}` → `stretch:pass` | **pass** |
| `/submit/m4` wrong value → `{"correct":false}`, no false credit | **pass** |
| `/reset/m4` clears both checks | **pass** |

**S4/M4 grading spine verified** — the actual pass/fail mechanism (`/submit` → audit log → `/validate` query) works exactly as designed and does not depend on model output (there is no model in this module) or on the scanner tool. The one open defect is confined to the standalone `scan_artifact.py` helper's handling of non-pickle files; see Step 1 for the root cause and suggested fix direction.
