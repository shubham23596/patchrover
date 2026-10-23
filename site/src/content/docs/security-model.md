---
title: Security model
description: Trust boundaries, fail-closed behavior, and read-only collection.
---

PatchRover is designed to support a human incident-response process, not replace it.

## Trust boundaries

- Packs are untrusted until strict decoding, policy checks, expiry checks, and signature verification succeed.
- Repositories, SBOMs, image references, evidence files, and Kubernetes metadata are untrusted input.
- Kubernetes access requires an explicit context. The collector invokes `kubectl` with fixed arguments for pod metadata only.
- Optional AI must use an explicitly configured local or BYOK provider. There is no silent cloud fallback, upload, or model download.
- Receipt integrity and signer identity are separate claims.

## Deterministic decisions

Only structured matcher rules decide verdicts. Missing or contradictory evidence returns `unknown`. AI may explain a result or draft prose, but it cannot override the deterministic engine.

## Default protections

- No production writes or autonomous deployments.
- No arbitrary commands from packs.
- Evidence files are size-limited and must be regular files.
- Repository collection skips VCS data, dependencies, virtual environments, and build outputs.
- Output files are not overwritten unless `--force` is explicit.
- Receipt identifiers are tokenized; public sharing is opt-in.

See the repository `THREAT_MODEL.md`, `SECURITY.md`, and `RESPONSIBLE_USE.md` before deploying PatchRover in a real environment.
