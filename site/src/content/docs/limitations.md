---
title: Limitations
description: What the current PatchRover release does not prove or automate.
---

The current release is pre-1.0 and is not a security guarantee.

- A fixed verdict covers only evidence that was supplied and rules present in the selected pack.
- A receipt does not prove that the wider organization or cluster is secure.
- The v1 registry signer is device-bound in one company maintainer's macOS Keychain. Independent custody, recovery, rotation rehearsal, and external audit remain incomplete.
- Kubernetes evidence is currently pod/container metadata; controllers, jobs, rollback history, registries, nodes, and caches require additional operational checks.
- Live OCI resolution is opt-in and manifest-only. It records the manifest or index digest observed at that moment; it does not download layers, select a platform child from a multi-platform index, or discover registry-attached SBOMs.
- The current collectors cover a narrow set of dependency files and SBOM formats.
- Autonomous repository fixes are line-specific dependency replacements and stop at a pull request; PatchRover does not merge or deploy them.
- Credential automation supports exact HashiCorp Vault database root rotations only. It does not change human passwords or cover every secrets provider.
- Advisory monitoring is structured and allowlisted. It is not a general web crawler, and uncovered advisories require a reviewed signed pack before remediation.
- CI exercises disposable OCI images and a temporary local Kubernetes cluster. That synthetic coverage does not replace validation against each customer's registry, cluster policy, and network path.
- LiteLLM incident content is provisional and can change as the upstream investigation evolves.
- Windows is not supported in the initial release.

Unsupported evidence must remain `unknown`; operators should not reinterpret it as `not_affected`.
