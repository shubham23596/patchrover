# Autonomous agent

PatchRover can continuously monitor structured authoritative advisories, reassess explicitly configured assets, and carry out two bounded actions: open a dependency-remediation pull request and rotate an explicitly named HashiCorp Vault database root credential.

It does **not** change employee passwords, browse arbitrary news pages, execute pack-provided code, run a general shell, deploy workloads, merge pull requests, or restart production. Those boundaries are intentional. A security bot with unrestricted credentials would create a new high-impact attack path.

## Modes

- `observe` records affected targets and suggested actions without making an approval queue.
- `propose` creates pending actions. An operator approves an exact action ID, and the next run executes it.
- `authorized` automatically executes only action types listed in `policy.autoActions`, up to `maxActionsPerRun`. Other actions remain pending.

Missing or conflicting evidence stays `unknown`. News without a signed Response Pack is recorded as advisory intelligence; it cannot produce a safe verdict or automatic fix.

## Start safely

Copy [`examples/agent.propose.json`](../examples/agent.propose.json), replace the example repository and Vault address, and keep `mode` set to `propose` until the evidence and provider permissions have been reviewed.

```sh
export PATCHROVER_GITHUB_TOKEN='a fine-grained token scoped to contents and pull requests'
export PATCHROVER_VAULT_TOKEN='a narrowly scoped token for database/rotate-root on one named connection'

patchrover agent run --config examples/agent.propose.json --once
patchrover agent status --state .patchrover/agent-state.json
patchrover agent approve --state .patchrover/agent-state.json --action ACTION_ID
patchrover agent run --config examples/agent.propose.json --once
```

Token values are read from the named environment variables and are never written to configuration or state. The state file is owner-readable and contains a hash-chained audit log. Any edit to an existing audit entry causes loading to fail.

## Advisory sources

The alpha supports:

- CISA Known Exploited Vulnerabilities JSON;
- GitHub Global Security Advisories JSON;
- allowlisted RSS or Atom feeds from official publishers.

Every endpoint must be HTTPS and its exact hostname must appear in `allowedHosts`. Response bodies are size-limited, requests time out, redirects remain subject to the standard HTTP client, and no feed content is executed.

## Repository safety

PatchRover reads a specific file from the target repository and confirms its SHA-256 content matches the version that was assessed. It performs one line-specific dependency replacement, creates a dedicated branch, and opens a pull request. If the file changed after assessment, the action fails closed. It never merges the pull request.

## Machine credential safety

The only alpha credential action is HashiCorp Vault's database root rotation endpoint for exact resource names declared on the target. This covers a managed service credential, not a person's password. Adding another provider requires a typed integration and tests; a generic password-changing or command-running adapter is prohibited.

## Deployment model

Run the agent inside the customer's own CI or infrastructure. The public website is static on GitHub Pages and never receives repositories, credentials, evidence, or telemetry. A hosted control plane is intentionally deferred.
