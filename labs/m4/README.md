# M4 — Supply Chain Audit

This lab drops a set of ML pipeline artifacts and dependency pins into
`labs/m4/`. Your job: audit them for a poisoned model artifact and a
vulnerable dependency, then submit your findings via the M4 panel.

## What's here

- `artifacts/community_model.pkl` — a "community-contributed" model
  checkpoint pulled into the pipeline.
- `artifacts/embedding_model.safetensors` — an embedding model checkpoint.
- `requirements-vulnerable.txt` — the pinned dependencies for this pipeline.

## How to audit

1. Scan the artifacts for unsafe deserialization:

   ```bash
   python -m halcyon.scan_artifact labs/m4/artifacts/*
   ```

   A `MALICIOUS` verdict means the artifact contains opcodes capable of
   arbitrary code execution when unpickled. **Never `pickle.load` a
   flagged artifact** — the scan is static and does not execute anything.

2. Audit the dependency pins for known CVEs:

   ```bash
   pip-audit -r labs/m4/requirements-vulnerable.txt
   ```

   (No `pip-audit`? Look up each pin manually against the NVD/OSV database.)

3. Submit your findings — the sha256 of the poisoned artifact, and the
   name of the vulnerable package — via the M4 panel.
