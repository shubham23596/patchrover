# Autonomous agent

PatchRover can continuously monitor structured authoritative advisories, reassess explicitly configured assets, and carry out two bounded actions: open a dependency-remediation pull request and rotate an explicitly named HashiCorp Vault database root credential.

It does **not** change employee passwords, browse arbitrary news pages, execute pack-provided code, run a general shell, deploy workloads, merge pull requests, or restart production. Those boundaries are intentional. A security bot with unrestricted credentials would create a new high-impact attack path.

## Modes

- `observe` records affected targets and suggested actions without making an approval queue.
- `propose` creates pending actions. In the open-source workflow, an operator reviews one exact action and explicitly approves its execution. With the commercial integration, the agent submits bounded proposal metadata to the team approval inbox and a customer-hosted runner executes only after approval.

There is no automatic-approval mode. Every write action requires an exact recorded approval.

Missing or conflicting evidence stays `unknown`. News without a signed Response Pack is recorded as advisory intelligence; it cannot produce a safe verdict or proposed fix.

## Start safely

Copy [`examples/agent.propose.json`](../examples/agent.propose.json), replace the example repository and Vault address, and keep `mode` set to `propose` until the evidence and provider permissions have been reviewed.

```sh
export PATCHROVER_GITHUB_TOKEN='a fine-grained token scoped to contents and pull requests'
export PATCHROVER_VAULT_TOKEN='a narrowly scoped token for database/rotate-root on one named connection'

patchrover agent run --config examples/agent.propose.json --once
patchrover agent status --state .patchrover/agent-state.json
patchrover agent review --config examples/agent.propose.json --action ACTION_ID
```

The review command shows the exact action and asks the operator to type `yes`. Any other answer cancels. Approval is written to the hash-chained audit log before that one action runs. Token values are read from the named environment variables and are never written to configuration or state. Any edit to an existing audit entry causes loading to fail.

## Commercial approval inbox

Commercial customers replace the local `github` and `vault` write integrations with one control-plane connection:

```json
{
  "integrations": {
    "controlPlane": {
      "url": "https://control.patchrover.example",
      "tokenEnv": "PATCHROVER_CONTROL_PLANE_TOKEN"
    }
  }
}
```

The public agent sends only the action type, exact target, Pack ID, Trail ID, affected verdict, and the bounded change metadata needed for approval. It never sends repository contents, GitHub or Vault credentials, Kubernetes Secrets, or human passwords. Accepted actions become `submitted` locally and cannot be executed with the local review command. Repeated submission after a lost response is safe because the action ID is deterministic and the control plane is idempotent.

## Advisory sources

The current release supports:

- CISA Known Exploited Vulnerabilities JSON;
- GitHub Global Security Advisories JSON;
- allowlisted RSS or Atom feeds from official publishers.

Every endpoint must be HTTPS and its exact hostname must appear in `allowedHosts`. Response bodies are size-limited, requests time out, redirects remain subject to the standard HTTP client, and no feed content is executed.

## Repository safety

PatchRover reads a specific file from the target repository and confirms its SHA-256 content matches the version that was assessed. It performs one line-specific dependency replacement, creates a dedicated branch, and opens a pull request. If the file changed after assessment, the action fails closed. It never merges the pull request.

## Machine credential safety

The only credential action is HashiCorp Vault's database root rotation endpoint for exact resource names declared on the target. This covers a managed service credential, not a person's password. Adding another provider requires a typed integration and tests; a generic password-changing or command-running adapter is prohibited.

## Deployment model

Run the agent and commercial remediation runner inside the customer's own CI or infrastructure. The public website is static on GitHub Pages and never receives repositories, credentials, evidence, or telemetry. The optional commercial control plane receives only bounded approval metadata; write credentials remain in the customer-hosted runner.
