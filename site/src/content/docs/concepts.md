---
title: Packs, trails, and receipts
description: The three public concepts that make PatchRover incident evidence reviewable.
---

## Packs

A **Pack** is signed, declarative incident-response content. It binds advisory identifiers and official sources to structured affected/fixed rules, remediation guidance, verification requirements, expiry, author, and review state.

Packs cannot contain executable collectors or arbitrary shell commands. The CLI accepts only its compiled-in collectors.

## Trails

A **Trail** is an evidence path from an advisory to an observed source dependency, built image, and running workload. Each decisive finding links to an `EvidenceRef` with source, timestamp, asset identity, collector, digest or version, runtime status, and confidence.

The overall verdict is conservative:

- `affected`: an exact affected version, range, or digest matched.
- `fixed`: every relevant observation matched an explicit fixed rule.
- `unknown`: evidence is missing, contradictory, unparseable, or outside pack rules.
- `not_affected`: reserved for explicit absence rules; PatchRover never infers it from missing data.

## Receipts

A **Receipt** is a redacted signed attestation of observed closure. PatchRover uses a DSSE envelope, an in-toto Statement v1, and embedded OpenVEX-compatible fixed statements.

Repository, cluster, namespace, workload, pod, and source identifiers are tokenized by default. The embedded signature proves that receipt bytes were not modified but does not establish identity. Identity is marked trusted only when a standard Sigstore v0.3+ bundle covers the exact receipt bytes and matches the operator's exact certificate identity and OIDC issuer policy, including certificate-transparency and transparency-log verification.
