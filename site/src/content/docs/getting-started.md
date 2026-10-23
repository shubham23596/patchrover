---
title: Getting started
description: Build PatchRover locally and run the safe, account-free demo.
---

PatchRover is a local-first incident-response evidence tool. Collection is read-only. The optional self-hosted agent can open a bounded pull request or rotate an exact allowlisted Vault database credential under policy, but it never merges, deploys, changes workloads, or changes human passwords.

## Requirements

- Go 1.27 or later
- macOS or Linux on x86-64 or ARM64
- `kubectl` only when you explicitly use `--kube-context`

No account, model, API key, container runtime, or network request is needed for the demo.

## Run the deterministic demo

From a PatchRover checkout:

```sh
go run ./cmd/patchrover demo
go run ./cmd/patchrover agent demo
```

The demo creates temporary synthetic source and Kubernetes metadata, validates a signed response pack, produces an affected trail, drafts a local remediation proposal, verifies fixed evidence, and independently checks a signed receipt. Temporary files are removed at the end.

The agent demo separately exercises advisory correlation, deterministic assessment, and the stale-content-protected remediation path without contacting GitHub or Vault.

## Assess a synthetic fixture

```sh
go run ./cmd/patchrover assess \
  --pack packs/php-2026-rce \
  --repo packs/php-2026-rce/fixtures/affected \
  --kube-snapshot packs/php-2026-rce/fixtures/affected/pods.json \
  --out patchrover-trail.json
```

An affected assessment exits with status `2`; an unknown assessment exits with `3`. This lets CI distinguish a deterministic finding from an operational error.

## Review before real use

Read the [security model](../security-model/) and [limitations](../limitations/). Only inspect repositories, artifacts, and clusters you are authorized to access. Bundled packs must validate against the `patchrover-registry-v1` public trust root; contributor self-signatures are not registry-trusted.
