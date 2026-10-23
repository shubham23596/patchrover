---
title: Security model
description: Trust boundaries, fail-closed behavior, and read-only collection.
---

PatchRover automates bounded incident-response work while keeping production deployment and human identity changes outside its authority.

## Trust boundaries

- Packs are untrusted until strict decoding, policy checks, expiry checks, and signature verification succeed.
- Repositories, SBOMs, image references, evidence files, and Kubernetes metadata are untrusted input.
- Kubernetes access requires an explicit context. The collector invokes `kubectl` with fixed arguments for pod metadata only.
- Optional AI must use an explicitly configured local or BYOK provider. There is no silent cloud fallback, upload, or model download.
- Receipt integrity and signer identity are separate claims.

## Deterministic decisions

Only structured matcher rules decide verdicts. Missing or contradictory evidence returns `unknown`. AI may explain a result or draft prose, but it cannot override the deterministic engine.

## Default protections

- No production workload writes, merges, autonomous deployments, or human-password changes.
- Agent writes are limited to typed GitHub pull requests and exact Vault database root rotations under explicit policy.
- Repository content must match the SHA-256 assessed version before an automatic edit.
- Agent state has strict decoding and a hash-chained audit history.
- No arbitrary commands from packs.
- Evidence files are size-limited and must be regular files.
- Repository collection skips VCS data, dependencies, virtual environments, and build outputs.
- Output files are not overwritten unless `--force` is explicit.
- Receipt identifiers are tokenized; public sharing is opt-in.

See the repository `THREAT_MODEL.md`, `SECURITY.md`, and `RESPONSIBLE_USE.md` before deploying PatchRover in a real environment.
