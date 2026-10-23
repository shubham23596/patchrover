# Governance

PatchRover uses a maintainer-led open-source model during its pre-1.0 stage.

## Roles

- **Contributors** propose code, documentation, fixtures, or response-pack changes.
- **Maintainers** review changes, triage issues, and steward releases.
- **Security maintainers** review pack safety, signatures, threat-model changes, and private reports.

## Decisions

- Routine changes require one maintainer approval and passing required checks.
- Verified response-pack releases, trust-root changes, receipt schema changes, and security-boundary changes require two security-maintainer approvals.
- A maintainer cannot be the sole approver of their own response-pack signature or trust-root rotation.
- Revocation can be performed immediately by a security maintainer and must receive a second review afterward.

## Independence and continuity

The repository is published from founder Shubham Jain's `shubham23596` GitHub account, with contributions attributed to their authors. The Singapore operating company controls the project IP, release identity, future domain, and commercial infrastructure. Before a stable production release, add at least one additional trusted repository administrator using secure 2FA so continuity does not depend on one account.

## Changes to governance

Material governance changes require a public proposal and a recorded maintainer decision. A foundation is not planned during the pre-1.0 stage; it may be reconsidered only after meaningful independent adoption.

