---
title: Governance
description: Ownership, contribution, release, and safety governance for PatchRover.
---

The public home is `github.com/shubham23596/patchrover`, visibly attributing founder and lead maintainer Shubham Jain. The Singapore operating company controls the project IP, release identity, future domain, and commercial service. The repository can move to a company organization later without changing the Apache-2.0 license.

Before a stable production release, the project must have:

- A second trusted repository administrator.
- Passkeys or secure two-factor authentication for owners and release maintainers.
- Protected branches and tags, required CODEOWNERS review, and read-only default workflow permissions.
- Immutable releases and GitHub build-provenance attestations.
- Independent recovery or keyless rotation for the company-controlled `patchrover-registry-v1` signer.

Core code and public incident packs use Apache-2.0. Contributions use a Developer Certificate of Origin sign-off. The trademark policy protects the PatchRover name without restricting compatible forks from describing themselves accurately.

Critical post-disclosure safety content should remain public. The commercial business sells operational speed, private content, fleet visibility, integrations, governance, support, and SLAs.
