# Threat Model

## Assets

- Source repositories and dependency metadata.
- SBOMs, OCI image references and digests.
- Kubernetes workload metadata.
- Response-pack integrity and registry trust.
- Trails, proposals, and production receipts.

## Trust boundaries

1. Response packs are untrusted input until schema and signature validation succeeds.
2. Repository files, SBOMs, Kubernetes metadata, and advisory text are untrusted data.
3. Deterministic matchers alone decide verdicts.
4. Any future model is an explanation/proposal boundary with no direct production credentials or tools.
5. Receipt integrity is distinct from signer identity trust.

## Primary threats and controls

| Threat | Control |
| --- | --- |
| Malicious pack executes code | Strict JSON schema represented by typed decoding; unknown fields rejected; no command field exists. |
| False-safe verdict | Missing, contradictory, unsupported, or unrecognized evidence returns `unknown`; `not_affected` requires an explicit future absence proof. |
| Compromised registry pack | Ed25519 signature verification against the compiled trusted registry key set, source citations, review state, expiry, revocation state, and CI fixtures. |
| Prompt injection | Models are not part of verdict generation and receive structured evidence rather than authority. |
| Kubernetes privilege abuse | Explicit context, fixed `kubectl get pods` arguments, request timeout, no Secrets, no exec, no mutation. |
| Receipt leaks infrastructure names | Stable salted redaction by default; source paths and cluster/workload identifiers are excluded. |
| Receipt tampering | DSSE signature verification and subject digest checks. |
| Self-signed receipt mistaken for trusted identity | Verifier reports integrity and identity trust separately; alpha receipts are explicitly untrusted-self-signed. |
| Compromised GitHub workflow | Minimal permissions, pinned action SHAs, Dependabot, CodeQL, repository-enforced protected releases, and signed provenance. |

## Residual risks

- Dependency files, image tags, and SBOMs may be stale or incomplete.
- An OCI tag is mutable and is not equivalent to a digest.
- Kubernetes pod metadata proves an observed image identity, not absence of compromise.
- A fixed version does not prove that unrelated vulnerabilities or persistence are absent.
- The v1 response-pack signing seed is device-bound in one company maintainer's macOS Keychain. Independent custody, recovery, rotation rehearsal, and external audit are not yet complete.

These limitations must remain visible in CLI and website output.

