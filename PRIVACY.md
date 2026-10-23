# Privacy

PatchRover is local-first.

## Default behavior

- Repository, SBOM, OCI reference, and Kubernetes metadata are processed locally.
- No analytics, telemetry, account, hosted scanner, or model call is enabled.
- No source code is included in a production receipt.
- Repository paths, Kubernetes contexts, namespaces, pod names, and workload names are redacted from receipts by default.
- The CLI never reads Kubernetes Secrets and never invokes `kubectl exec`.

## Optional network behavior

The default workflow does not contact a model or hosted PatchRover service. A user may explicitly:

- invoke an installed `kubectl` binary against a named context for fixed, read-only pod metadata collection;
- request an explanation from a loopback Ollama endpoint using an already-installed model; or
- configure an HTTPS OpenAI-compatible BYOK endpoint, model name, and API-key environment variable;
- run the self-hosted agent against exact allowlisted advisory, GitHub API, or Vault endpoints; or
- resolve an explicitly supplied OCI tag against exact allowlisted registry and token-service HTTPS hosts. A private-registry bearer token is read only from the named environment variable and is not stored in evidence, trails, state, or receipts.

The agent reads provider tokens only from named environment variables. Token values are not written to configuration, state, trails, receipts, or audit entries. Repository pull requests transmit only the bounded changed file to the configured GitHub repository. Vault rotation sends no password value; it invokes the exact provider rotation endpoint for a configured database connection.

PatchRover never downloads a model, silently falls back to a cloud provider, or enables these network paths without explicit configuration. Provider prose is untrusted and cannot alter evidence, verdicts, or local diffs. Registry manifest resolution is independently disabled by default and never downloads image layers.

## Sharing

Receipts are written locally. Uploading or publishing them is solely the operator's explicit action. Review every receipt before sharing it outside the organization.

