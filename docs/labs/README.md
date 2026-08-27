# Eiger Lab Guides

Courseware for the 8 Eiger teaching modules (M1–M8, layers L0→L5) and the separate Treasury Heist capstone. Kept with the app so the UI, endpoints, and payloads stay versioned against the code they describe.

| File | Audience | Contents |
|---|---|---|
| [`test-runbook.md`](test-runbook.md) | **Trainer (QA)** | End-to-end vulnerable/hardened sweep, learner-UX checks, and Treasury Heist verification. Run this to confirm the lab is conference-ready. |
| [`trainer-guide.md`](trainer-guide.md) | **Trainer (facilitation)** | Per-module mechanism, **the solutions**, expected validation, defence retest, teaching notes, model tier, and capstone coaching. **Contains answers.** |
| [`participant-guide.md`](participant-guide.md) | **Participants** | Build/Break/Secure objectives plus the capstone brief, with hints but **no solutions**. Safe to hand out. |

**Reference material (not for distribution):** `../STATUS.md` (build status + honeytokens/markers), `../e2e/*.md` (per-module live-proof evidence with exact proven payloads), `../m4-instructor-demo.md` (the sandboxed pickle-RCE demo), `../../OPERATIONS.md` (deploy/run).

**Start here to test:** `test-runbook.md` → Phase 0 (bring up the stack).
