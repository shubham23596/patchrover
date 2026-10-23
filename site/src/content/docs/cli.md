---
title: CLI reference
description: PatchRover commands, evidence inputs, outputs, and exit codes.
---

## `patchrover demo`

Runs a deterministic end-to-end demonstration with temporary synthetic fixtures. It uses no network, model, account, vulnerable package, or production access.

## `patchrover assess --pack <ref>`

Validates a signed response pack, collects evidence, and writes a `Trail` JSON document. Supply at least one evidence source:

- `--repo <dir>`: requirements files, Poetry/uv locks, and Dockerfiles.
- `--sbom <file>`: CycloneDX or SPDX JSON.
- `--image <ref>`: an explicit OCI image reference.
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

## `patchrover receipt verify <file>`

Validates DSSE integrity and the signed in-toto statement. Integrity and identity trust are reported separately. Alpha receipts use ephemeral self-signed keys by default, so they do not claim externally trusted organizational identity.

## `patchrover pack validate <dir>`

Validates schema, expiry, review state, source URLs, deterministic matcher rules, and the Ed25519 signature. A directory resolves to its `pack.json`.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Command succeeded; assessment is fixed or an explicitly supported non-affected result. |
| `1` | Invalid input, failed integrity check, collection error, or other operational failure. |
| `2` | Assessment is affected. |
| `3` | Assessment is unknown. |
