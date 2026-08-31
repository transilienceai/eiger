# Security policy

## Deliberate vulnerabilities

Eiger is intentionally vulnerable training software. The attacks described in the
README, learner material, trainer guide, source comments, and `SEC_*` flag pairs are part
of the curriculum and are not security defects. This includes prompt injection, stored
XSS, unsafe authorization, RAG and MCP poisoning, unsafe pickle deserialization, pinned
vulnerable demonstration dependencies, and guardrail bypasses.

Do not report an intentional teaching vulnerability unless its behavior escapes the
documented lab boundary or remains active where the corresponding hardened control is
supposed to prevent it.

## What to report privately

Examples of unintended issues worth reporting include:

- escape from the documented container or per-participant boundary;
- exposure of a real secret, maintainer credential, or non-synthetic data;
- an unintended vulnerability in the hardened path;
- a build, dependency, or deployment issue that creates risk beyond the documented lab;
- a way the default Compose configuration becomes reachable beyond the local host.

Use GitHub's private vulnerability-reporting form for this repository when it is
available. If private reporting is unavailable, open a minimal issue requesting a private
contact channel; do not include exploit details, secrets, or real-world target data in a
public issue.

Include the affected revision, configuration, reproduction conditions, expected boundary,
and observed impact. Please test only against systems and data you own or are explicitly
authorized to assess.

## Supported version

Security-boundary fixes are made on the current `main` branch. Historical revisions and
the intentionally vulnerable teaching paths are not supported as secure software.
