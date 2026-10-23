---
title: Autonomous agent
description: Monitor authoritative advisories and run narrowly authorized remediation actions.
---

PatchRover's self-hosted agent continuously polls allowlisted structured sources, reassesses explicit assets with signed Response Packs, and creates an auditable action queue.

## Two modes

- `observe` records evidence and suggested actions without an approval queue.
- `propose` queues exact actions for human approval.

There is no automatic-approval mode. The open-source binary cannot execute a write action.

The commercial customer-hosted runner has only two write capabilities: open a bounded GitHub dependency-remediation pull request, and call HashiCorp Vault's database root rotation endpoint for an exact configured resource. It cannot change a human password, run arbitrary shell code, merge a pull request, deploy a workload, or restart production.

## Run one monitoring cycle

Copy `examples/agent.propose.json`, set your authorized repository and commercial control-plane endpoint, then supply a token with exact `submit` scope through the named environment variable. That token cannot lease or complete a fix; the customer runner uses a separate `execute` token that cannot submit findings.

```sh
patchrover agent run --config examples/agent.propose.json --once
patchrover agent status --state .patchrover/agent-state.json
```

The open-source agent records evidence and sends only bounded action metadata. It never receives repository or Vault write credentials. Tokens are never written to configuration or state, and tampering prevents the agent from loading its audit state.

## Team approval inbox

Commercial customers send a bounded proposal to the private approval inbox. The submission contains the exact action, Pack and Trail references, and change metadata needed for review. Repository contents, Kubernetes Secrets, GitHub tokens, Vault tokens, and human passwords are never sent.

After a person approves the exact action, a customer-hosted runner verifies its signed approval and applies only that fix. It never merges or deploys the result.

## Intelligence sources

PatchRover parses CISA Known Exploited Vulnerabilities JSON, GitHub Global Security Advisories JSON, and allowlisted official RSS/Atom feeds. Every endpoint must use HTTPS and an exact allowlisted hostname. Feed content is intelligence only: without a signed Response Pack it cannot create a deterministic verdict or proposed fix.
