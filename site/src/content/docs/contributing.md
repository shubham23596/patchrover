---
title: Contributing
description: How to contribute safe code and response packs to PatchRover.
---

PatchRover accepts code, documentation, and public post-disclosure response-pack contributions under Apache-2.0 with Developer Certificate of Origin sign-off.

## Before opening a change

- Use only synthetic fixtures. Never include a compromised artifact, exploit, credential, customer identifier, or victim data.
- Packs must stay declarative and may use only vetted built-in collectors.
- Link authoritative public HTTPS sources for every decisive incident rule.
- Preserve fail-closed behavior: missing or contradictory evidence stays `unknown`.
- Keep production access read-only and require an explicit Kubernetes context.

## Required checks

```bash
make verify
make build packs
cd site && npm ci && npm run build
```

Run the disposable OCI/Kubernetes workflow on a host with Docker, Kind, and kubectl when collectors or runtime verification change. Sign each commit with `Signed-off-by:` as described in the repository contribution guide.
