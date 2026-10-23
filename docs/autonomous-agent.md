# Autonomous agent

PatchRover can continuously monitor structured authoritative advisories and reassess explicitly configured assets. The open-source agent proposes fixes but cannot write to a repository or credential provider. The commercial customer-hosted runner can carry out two bounded actions after approval: open a dependency-remediation pull request or rotate an explicitly named HashiCorp Vault database root credential.

It does **not** change employee passwords, browse arbitrary news pages, execute pack-provided code, run a general shell, deploy workloads, merge pull requests, or restart production. Those boundaries are intentional. A security bot with unrestricted credentials would create a new high-impact attack path.

## Modes

- `observe` records affected targets and suggested actions without making an approval queue.
- `propose` creates pending actions. The open-source binary can record them locally or submit bounded metadata to the commercial team approval inbox. It cannot execute them.

There is no automatic-approval mode. Every write action requires an exact recorded approval.

Missing or conflicting evidence stays `unknown`. News without a signed Response Pack is recorded as advisory intelligence; it cannot produce a safe verdict or proposed fix.

## Start safely

Copy [`examples/agent.propose.json`](../examples/agent.propose.json), replace the example repository and control-plane address, and keep `mode` set to `propose`.

```sh
export PATCHROVER_CONTROL_PLANE_TOKEN='a submission-only commercial agent token'

patchrover agent run --config examples/agent.propose.json --once
patchrover agent status --state .patchrover/agent-state.json
```

The public agent sends a bounded proposal; it never receives repository or Vault write credentials. A person reviews the exact action in the commercial inbox. The customer-hosted commercial runner verifies the signed approval before applying it. Token values are read from named environment variables and are never written to configuration or state. Any edit to an existing audit entry causes loading to fail.

## Commercial approval inbox

Commercial customers configure one control-plane connection:

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

The commercial runner reads one specific file and confirms its SHA-256 content matches the approved version. It performs one line-specific dependency replacement, creates a dedicated branch, and opens a pull request. If the file changed after assessment, the action fails closed. It never merges the pull request.

## Machine credential safety

The only credential action is HashiCorp Vault's database root rotation endpoint for exact resource names declared on the target. This covers a managed service credential, not a person's password. Adding another provider requires a typed integration and tests; a generic password-changing or command-running adapter is prohibited.

## Deployment model

Run the agent and commercial remediation runner inside the customer's own CI or infrastructure. The public website is static on GitHub Pages and never receives repositories, credentials, evidence, or telemetry. The optional commercial control plane receives only bounded approval metadata; write credentials remain in the customer-hosted runner.
