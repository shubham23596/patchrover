---
title: CLI reference
description: PatchRover commands, evidence inputs, outputs, and exit codes.
---

## `patchrover assess --pack <ref>`

Validates a signed response pack, collects evidence, and writes a `Trail` JSON document. Supply at least one evidence source:

- `--repo <dir>`: requirements files, Poetry/uv locks, and Dockerfiles.
- `--sbom <file>`: CycloneDX or SPDX JSON.
- `--image <ref>`: an explicit OCI image reference or digest.
- `--resolve-image`: resolve a mutable tag to the manifest observed now and verify its digest.
- `--image-platform <platform>`: select one unambiguous Linux child manifest from a verified image index, such as `linux/amd64` or `linux/arm64/v8`. Digest, size, media type, and child bytes must all agree.
- `--registry-host <host>`: exact HTTPS registry or token-service host; repeat when both are required. Docker Hub, for example, needs `registry-1.docker.io` and `auth.docker.io`.
- `--registry-token-env <name>`: optional environment variable containing a read-only private-registry bearer token. The value is never stored.

Registry resolution is off by default. It fetches only size-limited OCI/Docker v2 indexes and manifests, forbids cross-host redirects, and never downloads image layers.
- `--evidence <file>`: a structured PatchRover evidence envelope.
- `--kube-snapshot <file>`: an offline Kubernetes PodList.
- `--kube-context <name>`: an explicit context; PatchRover invokes fixed-argument, read-only pod metadata collection.

## `patchrover propose --trail <file>`

Requires `--pack` and the repository used for the assessment. Writes a Markdown explanation, local unified diff where an exact safe replacement is possible, tests, operational checks, and required approvals. It does not change the source tree.

Optional AI explanation is disabled by default:

```sh
patchrover propose ... --ai-provider ollama --ai-model <already-installed-model>
```

Ollama is restricted to loopback. PatchRover never downloads a model. An explicit `openai-compatible` provider requires an HTTPS endpoint, model, and the name of a BYOK environment variable. Provider failure stops the command—there is no silent fallback—and generated prose is labeled as untrusted, non-evidence content that cannot affect the deterministic result.

## `patchrover verify --trail <file>`

Re-collects fresh evidence under the same signed pack. A receipt is created only when the trail is `fixed`, runtime evidence is required and present, and an immutable SHA-256 runtime digest can become the in-toto subject.

## `patchrover receipt verify [Sigstore flags] <file>`

Validates DSSE integrity and the signed in-toto statement. Integrity and identity trust are reported separately. Locally created receipts use ephemeral self-signed keys by default and remain untrusted.

To establish organization trust, first create the receipt with `patchrover verify --identity <exact Fulcio certificate identity>`. Sign the exact receipt file with `cosign sign-blob --bundle`, then pass `--sigstore-bundle`, the same exact `--certificate-identity`, one exact `--certificate-oidc-issuer`, and exactly one trust-root option. `--sigstore-public-good` explicitly allows a public Sigstore TUF refresh; `--sigstore-trusted-root <file>` uses an offline or private trusted root. PatchRover accepts only standard Sigstore v0.3+ bundles and requires certificate-transparency and transparency-log verification.

## `patchrover pack validate <dir>`

Validates schema, expiry, review state, source URLs, deterministic matcher rules, and the Ed25519 signature. A directory resolves to its `pack.json`.

## `patchrover agent`

- `agent run --config <file> [--once]` monitors sources and targets, then records proposed actions or submits them to the commercial approval inbox.
- `agent status --state <file>` reports target verdicts and action states.

The agent supports `observe` and `propose` modes. The open-source binary has no write capability. Commercial customer-hosted runners can open one approved GitHub pull request or rotate one approved HashiCorp Vault database root credential. They have no human-password, merge, deployment, or arbitrary-shell action.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Command succeeded; assessment is fixed or an explicitly supported non-affected result. |
| `1` | Invalid input, failed integrity check, collection error, or other operational failure. |
| `2` | Assessment is affected. |
| `3` | Assessment is unknown. |
