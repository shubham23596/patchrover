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
- configure an HTTPS OpenAI-compatible BYOK endpoint, model name, and API-key environment variable.

PatchRover never downloads a model, silently falls back to a cloud provider, or enables these network paths without their explicit flags. Provider prose is untrusted and cannot alter evidence, verdicts, or local diffs. Future registry downloads and hosted integrations must remain opt-in, documented, and independently disableable.

## Sharing

Receipts are written locally. Uploading or publishing them is solely the operator's explicit action. Review every receipt before sharing it outside the organization.

