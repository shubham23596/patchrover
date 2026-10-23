---
title: Getting started
description: Build PatchRover, assess an approved target, and review a proposed fix.
---

PatchRover is a local-first incident-response agent. The open-source binary is read-only. In `propose` mode, it finds a supported issue and prepares one exact action. Commercial customers can send that action to a team inbox for approval and customer-runner execution. PatchRover never merges, deploys, changes workloads, or changes human passwords.

## Requirements

- Go 1.27.3 or later
- macOS or Linux on x86-64 or ARM64
- `kubectl` only when you explicitly use `--kube-context`
- A commercial control-plane submission token only when using the team approval inbox

## Build PatchRover

From a PatchRover checkout:

```sh
make build
```

## Run a first assessment

```sh
bin/patchrover assess \
  --pack packs/php-2026-rce \
  --repo packs/php-2026-rce/fixtures/affected \
  --kube-snapshot packs/php-2026-rce/fixtures/affected/pods.json \
  --out patchrover-trail.json
```

An affected assessment exits with status `2`; an unknown assessment exits with `3`. This lets CI distinguish a deterministic finding from an operational error.

To resolve an authorized public image tag to the manifest digest observed now:

```sh
bin/patchrover assess \
  --pack packs/litellm-1.107.0-compromise \
  --image ghcr.io/berriai/litellm:main-latest \
  --resolve-image \
  --image-platform linux/amd64 \
  --registry-host ghcr.io \
  --out patchrover-trail.json
```

Resolution is disabled unless requested. `--image-platform` selects the verified child digest that actually runs on that Linux platform; ambiguous or missing matches fail closed. For registries with a separate public token service, repeat `--registry-host` for that exact host. Private-registry tokens are read from a named environment variable with `--registry-token-env`; their values are never stored.

## Send a fix for team approval

Copy `examples/agent.propose.json` and replace its example paths, repository, and provider endpoints with resources you are authorized to use. Keep `mode` set to `propose`.

```sh
bin/patchrover agent run --config examples/agent.propose.json --once
bin/patchrover agent status --state .patchrover/agent-state.json
```

The public agent remains read-only. It submits only bounded action metadata to the commercial inbox. A person approves or rejects the exact action there; only a signed customer-hosted commercial runner can apply it.

## Review before real use

Read the [security model](../security-model/) and [limitations](../limitations/). Only inspect repositories, artifacts, and clusters you are authorized to access. Bundled packs must validate against the `patchrover-registry-v1` public trust root; contributor self-signatures are not registry-trusted.
