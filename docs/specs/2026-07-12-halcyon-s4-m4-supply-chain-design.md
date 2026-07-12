# Halcyon S4 — M4 (ML / AI Supply Chain) — Design

**Date:** 2026-07-12
**Slice:** S4. Reuses the S1 spine (audit log, flags, `/validate` + `/reset`, progress) but is **structurally different** from M1–M3: there is **no Halo/LLM turn to observe**. M4 is a **codebase supply-chain audit** — participants get the repo and find planted risks.
**Scope (decided 2026-07-12):** **unified** — two findings: (1) a **poisoned model artifact** (pickle deserialization RCE) and (2) a **vulnerable/malicious pinned dependency**. Plus the `SEC_ARTIFACT_VERIFICATION` hardening.
**Status:** Design — for review before build.

---

## 1. What M4 teaches

- **Theme:** "Red-team the AI supply chain." Two supply-chain risk classes that both live *in the codebase*:
  - **Poisoned model (LLM03/LLM05):** Halcyon loads a model/embedding artifact via `pickle.load` from an untrusted source → deserialization executes code (RCE).
  - **Vulnerable dependency (supply chain / SCA):** a pinned package with a known CVE (or a typosquat/malicious name) in a lab manifest.
- **Delivery:** participants are given read access to the repo + a provided static scanner. They **audit → identify → submit** findings; then study the hardened diff.
- **Break (RCE):** **instructor-led demo only** (destructive/slow). Participants do NOT execute the RCE themselves (per-participant RCE needs the container fleet, a later Ops slice). The scanner is **static** — it never deserializes anything.

## 2. How validation works here (mechanism, not model words — adapted)

No model behavior to observe, so the graded mechanism is a **server-side check of a submitted finding against a known-bad answer** — deterministic, and still an append-only-audit-log query for pass/fail:

- `POST /submit/m4 {session_id, finding_type, value}`; `finding_type ∈ {"malicious_artifact", "vulnerable_dependency"}`.
- The server compares `value` to the server-side known-bad answer (artifact **sha256**, or package **name**), and on a correct match records an audit event.
- `GET /validate/m4?session=…` queries the log. Pure, deterministic, robust to how they phrase the submission (hash/name normalized).

## 3. New pieces (M4 deltas)

| Unit | Change |
|---|---|
| `config.py` | add `sec_artifact_verification` (mode-profiled) |
| `halcyon/artifacts.py` (new) | the **in-app vulnerable load path**: `load_artifact(path)` — `vulnerable` = `pickle.load`; `secure` = safetensors-only + **hash-pin** against an allowlist, reject anything else. This is the real code participants find. **Never called on user input in the app**; the RCE fixture is only for the instructor demo. |
| `halcyon/scan_artifact.py` (new) | provided **static** pickle-opcode scanner (`python -m halcyon.scan_artifact <file>`): uses `pickletools.genops`, flags dangerous opcodes (`GLOBAL`/`STACK_GLOBAL` to `os`/`subprocess`/`builtins`, `REDUCE`). Reports findings + the file's sha256. Never unpickles. |
| `labs/m4/` (new) | the audit target fixtures: `artifacts/` (benign `.safetensors`-style + one **poisoned** `.pkl`), a `build_poisoned.py` that generates the poisoned pickle deterministically (pickling is safe; only unpickling executes), and `requirements-vulnerable.txt` with a **planted known-CVE pinned dependency**. Isolated from the app's real `pyproject.toml`/`uv.lock` so our own build is never compromised. |
| `halcyon/m4_answers.py` (new) | server-side known-bad answers (poisoned artifact sha256, vulnerable package name) + normalizers. Not exposed via any read endpoint. |
| `audit.py` | `MALICIOUS_ARTIFACT_IDENTIFIED`, `VULNERABLE_DEPENDENCY_IDENTIFIED` |
| `web.py` | `POST /submit/m4` (check submission → record event), register `m4` validator, reset clears m4 events |
| `validators/m4.py` | core = `malicious_artifact_identified`; stretch = `vulnerable_dependency_identified` |
| UI | an M4 panel: brief instructions ("audit `labs/m4/`, run the scanner"), two submit boxes (artifact hash, package name) |
| tests | deterministic: correct/incorrect submissions; scanner flags the poisoned pickle and clears the benign ones; the secure loader rejects the pickle; validator |

New module id: `"m4"`.

## 4. The guard (`SEC_ARTIFACT_VERIFICATION`) — the diff is the lesson

`halcyon/artifacts.py::load_artifact(path)`:
- **off (vuln):** `return pickle.load(open(path,'rb'))` — arbitrary deserialization; loading the poisoned artifact executes code (the instructor-demo RCE).
- **on (secure):** reject any non-`.safetensors` file; require the file's sha256 to be in a pinned **allowlist**; load via a safetensors-only reader. The poisoned pickle is refused before any code runs. ~15 legible lines — the exact defense.

## 5. Core + stretch

Both planted findings are the exercise; core/stretch is the floor/ceiling split:
- **Core (mandatory):** identify the **poisoned model artifact** — run the scanner, submit its sha256 → `malicious_artifact_identified`. The AI-specific headline finding.
- **Stretch (fast finishers):** identify the **vulnerable pinned dependency** — SCA the lab manifest, submit its package name → `vulnerable_dependency_identified`.
- Both are deterministic (submission checked against a server-side known-bad answer). No upload surface.
- **Deferred (future enhancement):** "craft an evasive artifact" that beats the naive scanner — noted, not built in S4 (a clean naive-vs-strict static distinction is fiddly and the two findings already give a complete core+stretch).

## 6. What participants actually do (flow)

1. Clone/read the repo; open `labs/m4/`.
2. Run `python -m halcyon.scan_artifact labs/m4/artifacts/*` → the scanner flags the poisoned `.pkl` (dangerous `REDUCE`/`GLOBAL os.system`) and prints its sha256.
3. Run an SCA check (or read `requirements-vulnerable.txt` + a CVE lookup) → find the known-bad pinned package.
4. `POST /submit/m4` both findings → `GET /validate/m4` → core:pass.
5. Study `artifacts.py` with `SEC_ARTIFACT_VERIFICATION=on` (secure) to see the fix; instructor demos the actual RCE on the vulnerable loader.

## 7. Decisions / forks
1. **Static scanner + submit-the-finding validation** (no per-participant RCE). Matches spec §5 and the not-yet-built fleet. *Proceeding.*
2. **Deliberately-vulnerable material isolated in `labs/m4/`** (not in the app's real deps), so our own build/CI stays clean while participants still get a realistic "audit this repo" target. *Proceeding.*
3. **Core = poisoned artifact, stretch = vulnerable dependency** (both findings, floor/ceiling split). Evasive-artifact crafting deferred (see §5). *Proceeding.*
4. **Vulnerable dependency choice:** a real, well-known CVE'd pinned version (e.g. an old `pyyaml`/`jinja2`/`requests`) in the lab manifest, so `pip-audit`/`safety` flags it authentically. Exact package pinned at build time.

## 8. Out of scope for S4
No agent/tools/MCP/multi-agent (Day 2). No live RCE execution in the participant path (instructor demo only). No real change to the app's own dependencies. Deterministic tests; the scanner and secure loader are unit-tested; the instructor-demo RCE is documented, not automated.
