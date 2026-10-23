# PatchRover

**Track. Fix. Prove.**

PatchRover is an open-source, local-first incident response agent for critical vulnerability and software supply-chain events. It uses signed, declarative response packs to connect an advisory to repository evidence, container artifacts, and the workload actually running in production.

PatchRover is intentionally conservative:

- deterministic rules produce `affected`, `fixed`, `not_affected`, or `unknown` verdicts;
- missing or contradictory evidence remains `unknown`;
- response packs cannot execute arbitrary commands;
- Kubernetes collection is read-only and requires an explicit context;
- repository remediation is either proposed or opened as a bounded pull request under explicit policy; PatchRover never merges or deploys it;
- machine credentials can be rotated only through typed, allowlisted provider integrations; human passwords are out of scope;
- receipts redact internal identifiers by default;
- no model, account, cloud service, or API key is required for the core workflow.

> [!IMPORTANT]
> PatchRover is an early security tool, not a guarantee that a system is secure. Validate its evidence and remediation with qualified operators before acting.

## Five-minute demo

The demo is synthetic, deterministic, account-free, and does not execute vulnerable software.

```bash
go run ./cmd/patchrover demo
go run ./cmd/patchrover agent demo
```

It demonstrates a compromised dependency in source and a running workload, generates a local remediation proposal, simulates a human-approved deployment, verifies the fixed runtime digest, and creates a signed production receipt.

## Commands

```text
patchrover demo
patchrover assess --pack <pack-directory-or-json> --repo <path> [--sbom <file>] [--image <ref>] [--kube-context <name>]
patchrover propose --pack <pack-directory-or-json> --trail <trail.json> [explicit AI flags]
patchrover verify --pack <pack-directory-or-json> --trail <trail.json> [evidence flags]
patchrover receipt verify <receipt.json>
patchrover pack validate <pack-directory-or-json>
patchrover agent demo
patchrover agent run --config <agent.json> [--once]
patchrover agent status --state <state.json>
patchrover agent approve --state <state.json> --action <action-id>
```

`assess` exits with code `2` for `affected`, `3` for `unknown`, and `0` for a fixed or explicitly not-affected result. This makes it safe to use as a CI gate without confusing uncertainty with safety.

## Quick assessment

```bash
go build -o bin/patchrover ./cmd/patchrover

bin/patchrover assess \
  --pack packs/litellm-1.107.0-compromise/pack.json \
  --repo /path/to/authorized/repository \
  --out patchrover-trail.json

bin/patchrover propose \
  --pack packs/litellm-1.107.0-compromise/pack.json \
  --trail patchrover-trail.json \
  --out patchrover-proposal.md
```

Optional inputs:

- `--sbom`: CycloneDX JSON or SPDX JSON.
- `--image`: an OCI image reference; digests are evaluated, while unresolvable tags remain limited evidence.
- `--evidence`: an explicit PatchRover evidence JSON document.
- `--kube-context`: invokes only `kubectl --context CONTEXT get pods --all-namespaces -o json`; no exec, patch, apply, or secret API is used.
- `--kube-snapshot`: an offline pod-list JSON fixture or approved export.

Optional proposal explanation is off by default. `--ai-provider ollama --ai-model <installed-model>` calls only the loopback Ollama endpoint and never downloads a model. `--ai-provider openai-compatible` additionally requires an explicit HTTPS `--ai-endpoint`, `--ai-model`, and `--ai-key-env`; this is an explicit BYOK data transfer with no silent fallback. Provider prose is labeled untrusted and cannot alter evidence, verdicts, or local diffs.

## Safe autonomous mode

The self-hosted controller monitors allowlisted CISA KEV, GitHub Advisory, and official RSS/Atom feeds; continuously reassesses explicit targets; and can open a bounded dependency-remediation pull request or rotate an explicitly named HashiCorp Vault database root credential. It has `observe`, `propose`, and `authorized` modes. Authorized actions must be separately listed in policy and are rate-limited per run.

PatchRover has no arbitrary shell tool, no human-password action, no merge action, and no production-deployment action. Repository content must still match the exact SHA-256 observed during assessment or an automatic edit fails closed. See the [autonomous-agent guide](docs/autonomous-agent.md) and [example configuration](examples/agent.propose.json).

## Response packs

The first registry packs are:

- [`php-2026-rce`](packs/php-2026-rce/README.md), covering CVE-2026-109618 and CVE-2026-109619.
- [`litellm-1.107.0-compromise`](packs/litellm-1.107.0-compromise/README.md), covering the compromised LiteLLM 1.107.0 package and published image digests.

Packs are JSON rather than executable plugins. Unknown fields are rejected, HTTPS sources are required, and Ed25519 signatures are verified before assessment. Bundled packs are signed by the `patchrover-registry-v1` trust root. Only its public key is committed; the private seed is device-bound in a company maintainer's macOS Keychain and is read through a no-echo signing pipeline.

## Repository layout

- `cmd/patchrover`: CLI entry point.
- `internal`: pack validation, evidence collectors, assessment, proposals, receipts, and demo.
- `packs`: signed public response packs and synthetic fixtures.
- `site`: Astro/Starlight landing page and documentation.
- `.github`: CI, CodeQL, release, Pages, issue forms, and dependency updates.
- [`LAUNCH_CHECKLIST.md`](LAUNCH_CHECKLIST.md): exact company/GitHub controls and public-launch gates.

## Security and trust

Read the [threat model](THREAT_MODEL.md), [security policy](SECURITY.md), [responsible-use policy](RESPONSIBLE_USE.md), and [privacy model](PRIVACY.md) before using PatchRover with real infrastructure.

Production receipts are in-toto statements wrapped in a DSSE envelope with an embedded OpenVEX-compatible status document. The current local signer proves integrity but not an externally trusted identity. Organization-trusted or Sigstore keyless identity verification is a planned pre-beta requirement and is called out clearly in every verification result.

## Project status

PatchRover is a working alpha, not a production-ready security guarantee. Deterministic assessment, signed packs, evidence collection, local proposals, policy-controlled pull requests, typed Vault database credential rotation, advisory feeds, tamper-evident agent state, signed receipt verification, CI, and the static website are implemented. Multi-maintainer key custody, live OCI registry resolution, trusted Sigstore receipt identities, external security review, and production design-partner evidence remain future work.

GitHub Pages deploys automatically from `main`. Binary releases remain disabled until the release controls in the launch checklist are complete. The intended alpha home is `github.com/shubham23596/patchrover`, with its website served by GitHub Pages at `shubham23596.github.io/patchrover/`.

## License

Apache License 2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE), and [TRADEMARKS.md](TRADEMARKS.md).

