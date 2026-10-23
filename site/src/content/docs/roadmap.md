---
title: Roadmap
description: PatchRover's staged path from its open-source foundation to a commercial control plane.
---

## Open-source foundation

- Deterministic four-state verdict interface and signed response packs.
- Repository, SBOM, explicit OCI reference, opt-in verified registry-manifest and platform-child resolution, and read-only Kubernetes evidence.
- Local remediation proposals, approval-gated pull requests, typed Vault database credential rotation, and receipts with exact-policy Sigstore verification.
- Two public incident packs, reusable synthetic test fixtures, and a GitHub Action.
- Local Ollama and explicit HTTPS BYOK explanation adapters that cannot alter verdicts.
- Structured CISA KEV, GitHub Advisory, and official RSS/Atom monitoring with exact HTTPS host allowlists.

## Private design-partner beta

- Registry-attached SBOM discovery and verification.
- Organization signing policy, independent key custody, recovery, and rotation rehearsal.
- More repository and machine-credential provider integrations without adding a generic shell or password tool.
- Cross-repository and cross-cluster trail correlation.

## Commercial control plane

- Private packs, continuous monitoring, an approval inbox, approved fix application, fleet inventory, drift alerts, and history.
- The bounded agent-to-inbox bridge and customer-hosted remediation runner are implemented; hosted staging and production-readiness gates remain open.
- SSO/RBAC, audit retention, workflow integrations, SLAs, and incident support.

The open-source CLI, public pack format, public post-disclosure packs, and receipt verifier remain public. Progress is measured by repeat incident use, receipts, and paid conversions—not stars alone.
