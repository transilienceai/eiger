# M4 Instructor Demo — Live RCE on the Poisoned Artifact

**Date:** 2026-07-12
**Branch:** `s4-m4-supply-chain`
**Audience:** instructor only. This is **not** a participant-facing lab step — participants never call `halcyon.artifacts.load_artifact()` directly; they only run the static scanner (`halcyon.scan_artifact`, never deserializes) and submit findings via `/submit/m4`.

---

## ⚠️ WARNING

**Only run the vulnerable-load demo below inside an isolated, disposable container — never on a shared machine, a participant's machine, or the host running the Halcyon platform itself.**

`labs/m4/artifacts/community_model.pkl` is a real working pickle-deserialization exploit (see `labs/m4/build_poisoned.py`): unpickling it invokes `os.system("echo halcyon-m4-rce")` via `__reduce__`. The payload in this repo is intentionally harmless (it only echoes a fixed string), but the loading **mechanism** is genuine arbitrary code execution — `pickle.load()` on attacker-controlled bytes runs attacker-chosen code with the privileges of the process that loads it. Never load an untrusted pickle outside of a throwaway sandbox, and never adapt this demo to run a payload you haven't fully read.

---

## What this demonstrates

`halcyon/artifacts.py::load_artifact(path, settings)` is the in-app artifact loader, gated by `SEC_ARTIFACT_VERIFICATION` (defaults on when `HALCYON_MODE=secure`, off when `vulnerable`):

```python
def load_artifact(path: str | Path, settings: Settings) -> object:
    if settings.sec_artifact_verification:
        p = Path(path)
        if p.suffix != ".safetensors":
            raise ArtifactError(f"refused: only .safetensors permitted, got '{p.suffix}'")
        digest = sha256_file(p)
        if digest not in ALLOWED_HASHES:
            raise ArtifactError(f"refused: {digest} not in pinned allowlist")
        return p.read_bytes()  # teaching stub: a real reader would parse safetensors
    # VULNERABLE: arbitrary deserialization — loading a poisoned artifact executes code.
    with open(path, "rb") as f:
        return pickle.load(f)  # noqa: S301
```

- **`vulnerable`:** any file, any extension, straight into `pickle.load()`. Loading `community_model.pkl` executes its `__reduce__` payload.
- **`secure`:** rejects anything that isn't `.safetensors` outright (the poisoned file is `.pkl`, so it never reaches the hash check), and even a `.safetensors` file must match a pinned sha256 allowlist. The poisoned artifact is refused before a single byte is deserialized.

This function is **never called on user input in the running app** — it exists purely as the instructor-demo fixture and as the code participants read to see the fix. Participants' own path through M4 is: scan (static, safe) → submit finding → server-side answer check. See `docs/s4-e2e-checklist.md` for that flow.

---

## Demo 1 — Vulnerable mode: the payload fires

Run inside an isolated, disposable container (not the host, not a shared box). Example using a throwaway `python:3.12-slim` container with the repo bind-mounted **read-only** and removed immediately after (`--rm`); `halcyon.artifacts` and `halcyon.config` are pure stdlib, so no dependency install is needed for this demo:

```bash
docker run --rm -v "$(pwd)":/repo:ro -w /repo -e PYTHONPATH=/repo python:3.12-slim \
  python -c "from halcyon import artifacts; from halcyon.config import load_settings; artifacts.load_artifact('labs/m4/artifacts/community_model.pkl', load_settings({'HALCYON_MODE':'vulnerable'}))"
```

**This was actually executed** (isolated, disposable, `--rm` container; the payload only echoes a static string). Real output:

```
halcyon-m4-rce
```

That line comes from `os.system("echo halcyon-m4-rce")`, fired by `_Poisoned.__reduce__()` the instant `pickle.load()` deserializes the object — no explicit call to any attacker-controlled function was made by the loading code; unpickling alone was sufficient to execute it.

---

## Demo 2 — Secure mode: refused, never executes

Same isolated-container pattern, `HALCYON_MODE=secure`:

```bash
docker run --rm -v "$(pwd)":/repo:ro -w /repo -e PYTHONPATH=/repo python:3.12-slim \
  python -c "from halcyon import artifacts; from halcyon.config import load_settings; artifacts.load_artifact('labs/m4/artifacts/community_model.pkl', load_settings({'HALCYON_MODE':'secure'}))"
```

**This was actually executed.** Real output (raises, does not print `halcyon-m4-rce`, exit code 1):

```
Traceback (most recent call last):
  File "<string>", line 1, in <module>
  File "/repo/halcyon/artifacts.py", line 24, in load_artifact
    raise ArtifactError(f"refused: only .safetensors permitted, got '{p.suffix}'")
halcyon.artifacts.ArtifactError: refused: only .safetensors permitted, got '.pkl'
```

The extension check alone stops it here — `community_model.pkl` never gets far enough to reach the sha256 allowlist check, let alone `pickle.load()`. This is the whole guard: ~15 legible lines, reject-by-format before reject-by-hash, no deserialization of anything not already trusted.

---

## Delivery notes for the instructor

1. Show the scanner first (`python -m halcyon.scan_artifact labs/m4/artifacts/*`) — static, safe, this is what participants actually use.
2. Then say "here's what would have happened if the app had loaded this instead of just scanning it" and run **Demo 1** live, in the disposable container, screen-shared.
3. Immediately follow with **Demo 2** to show the fix is small and legible — the diff between vulnerable and secure `load_artifact` is the lesson (per the platform's "one build + security flags" rule).
4. Do not run Demo 1 against `labs/m4/artifacts/community_model.pkl` on any host or container that isn't thrown away immediately after. Do not reuse the demo container for anything else.
