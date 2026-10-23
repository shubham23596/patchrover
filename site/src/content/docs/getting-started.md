---
title: Getting started
description: Build PatchRover, assess an approved target, and review a proposed fix.
---

PatchRover is a local-first incident-response agent. Collection is read-only. In `propose` mode, it finds a supported issue, prepares one exact action, asks for human approval, and only then opens a bounded pull request or rotates an allowlisted Vault database credential. It never merges, deploys, changes workloads, or changes human passwords.

## Requirements

- Go 1.27 or later
- macOS or Linux on x86-64 or ARM64
- `kubectl` only when you explicitly use `--kube-context`
- A narrowly scoped GitHub or Vault token only when you approve a real action

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

## Ask for approval before fixing

Copy `examples/agent.propose.json` and replace its example paths, repository, and provider endpoints with resources you are authorized to use. Keep `mode` set to `propose`.

```sh
bin/patchrover agent run --config examples/agent.propose.json --once
bin/patchrover agent status --state .patchrover/agent-state.json
bin/patchrover agent review --config examples/agent.propose.json --action ACTION_ID
```

The review command shows the exact action and asks `Apply this exact fix? Type yes to approve:`. Any other answer cancels without changing the approval state. A successful approval is written to the audit chain before PatchRover applies that one action.

## Review before real use

Read the [security model](../security-model/) and [limitations](../limitations/). Only inspect repositories, artifacts, and clusters you are authorized to access. Bundled packs must validate against the `patchrover-registry-v1` public trust root; contributor self-signatures are not registry-trusted.
