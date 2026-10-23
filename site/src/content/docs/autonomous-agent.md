---
title: Autonomous agent
description: Monitor authoritative advisories and run narrowly authorized remediation actions.
---

PatchRover's self-hosted agent continuously polls allowlisted structured sources, reassesses explicit assets with signed Response Packs, and creates an auditable action queue.

## Three policy modes

- `observe` records evidence and suggested actions without an approval queue.
- `propose` queues exact actions for human approval.
- `authorized` executes only action types explicitly listed in `policy.autoActions`, with a per-run limit.

The alpha has only two write capabilities: open a bounded GitHub dependency-remediation pull request, and call HashiCorp Vault's database root rotation endpoint for an exact configured resource. It cannot change a human password, run arbitrary shell code, merge a pull request, deploy a workload, or restart production.

## Try the offline agent demo

```sh
go run ./cmd/patchrover agent demo
```

The demo uses a synthetic dependency and prepares the exact post-fix content without a network call or external mutation.

## Run one proposal cycle

Copy `examples/agent.propose.json`, set your authorized repository and provider endpoints, then supply narrowly scoped tokens through the named environment variables.

```sh
patchrover agent run --config examples/agent.propose.json --once
patchrover agent status --state .patchrover/agent-state.json
patchrover agent approve --state .patchrover/agent-state.json --action ACTION_ID
patchrover agent run --config examples/agent.propose.json --once
```

Tokens are never written to configuration or state. Repository edits fail if the current file no longer matches the SHA-256 content assessed by PatchRover. The audit log is hash-chained, and tampering prevents the agent from loading it.

## Intelligence sources

The alpha parses CISA Known Exploited Vulnerabilities JSON, GitHub Global Security Advisories JSON, and allowlisted official RSS/Atom feeds. Every endpoint must use HTTPS and an exact allowlisted hostname. Feed content is intelligence only: without a signed Response Pack it cannot create a deterministic verdict or automatic fix.
