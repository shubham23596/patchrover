---
title: Autonomous agent
description: Monitor authoritative advisories and run narrowly authorized remediation actions.
---

PatchRover's self-hosted agent continuously polls allowlisted structured sources, reassesses explicit assets with signed Response Packs, and creates an auditable action queue.

## Two modes

- `observe` records evidence and suggested actions without an approval queue.
- `propose` queues exact actions for human approval.

There is no automatic-approval mode. Every write action requires an exact recorded approval.

The current release has only two write capabilities: open a bounded GitHub dependency-remediation pull request, and call HashiCorp Vault's database root rotation endpoint for an exact configured resource. It cannot change a human password, run arbitrary shell code, merge a pull request, deploy a workload, or restart production.

## Run one approval-controlled cycle

Copy `examples/agent.propose.json`, set your authorized repository and provider endpoints, then supply narrowly scoped tokens through the named environment variables.

```sh
patchrover agent run --config examples/agent.propose.json --once
patchrover agent status --state .patchrover/agent-state.json
patchrover agent review --config examples/agent.propose.json --action ACTION_ID
```

The review command shows the exact change and requires the operator to type `yes`. Any other answer cancels without approval. Tokens are never written to configuration or state. Repository edits fail if the current file no longer matches the SHA-256 content assessed by PatchRover. Approval is recorded in the hash-chained audit log before the one approved action runs, and tampering prevents the agent from loading it.

## Team approval inbox

Commercial customers can send a bounded proposal to the private approval inbox instead of configuring local write credentials in the monitoring agent. The submission contains the exact action, Pack and Trail references, and change metadata needed for review. Repository contents, Kubernetes Secrets, GitHub tokens, Vault tokens, and human passwords are never sent.

After a person approves the exact action, a customer-hosted runner verifies its signed approval and applies only that fix. It never merges or deploys the result.

## Intelligence sources

PatchRover parses CISA Known Exploited Vulnerabilities JSON, GitHub Global Security Advisories JSON, and allowlisted official RSS/Atom feeds. Every endpoint must use HTTPS and an exact allowlisted hostname. Feed content is intelligence only: without a signed Response Pack it cannot create a deterministic verdict or proposed fix.
