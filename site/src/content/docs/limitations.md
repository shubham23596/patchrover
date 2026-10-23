---
title: Limitations
description: What the PatchRover alpha does not prove or automate.
---

The current release is a working alpha, not a security guarantee.

- A fixed verdict covers only evidence that was supplied and rules present in the selected pack.
- A receipt does not prove that the wider organization or cluster is secure.
- The v1 registry signer is device-bound in one company maintainer's macOS Keychain. Independent custody, recovery, rotation rehearsal, and external audit remain incomplete.
- Kubernetes evidence is currently pod/container metadata; controllers, jobs, rollback history, registries, nodes, and caches require additional operational checks.
- OCI references are inspected as provided. The alpha does not fetch registry manifests or layers.
- The current collectors cover a narrow set of dependency files and SBOM formats.
- Live disposable OCI and local-cluster end-to-end tests remain a launch gate on a host with a container runtime.
- LiteLLM incident content is provisional and can change as the upstream investigation evolves.
- Windows is not supported in the initial release.

Unsupported evidence must remain `unknown`; operators should not reinterpret it as `not_affected`.
