---
title: Response Pack v1alpha1
description: Authoring and validating PatchRover response packs.
---

`ResponsePack v1alpha1` is strict JSON. Unknown fields are rejected, making unreviewed executable behavior impossible to smuggle into a pack.

## Required content

- Metadata: stable ID, semantic pack version, title, summary, author, review state, publication time, and expiry.
- Advisories and authoritative HTTPS sources.
- Structured matchers for artifact kinds, names, affected versions/ranges/digests, and fixed versions/minimums.
- Remediation steps, tests, operational checks, and human approvals.
- Verification requirements, including whether runtime evidence is mandatory.
- Ed25519 signature material over canonical pack bytes.

## Review states

`verified` is for reviewed content supported by authoritative sources. `provisional` is for fast-moving incidents and produces a CLI warning. `revoked` fails validation.

Every pack expires. A changed rule requires a new version and signature; an old signed file is never silently reinterpreted.

## Contributor validation

```sh
go run ./cmd/patchrover pack validate packs/<pack-id>
go test -race ./...
```

Fixtures must be synthetic. Never commit a compromised wheel, image layer, malware sample, credential, exploit, or raw evidence copied from a victim environment.
