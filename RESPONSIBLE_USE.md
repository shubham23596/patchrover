# Responsible Use

PatchRover is built for defensive use on systems the operator owns or is authorized to assess.

Allowed uses include:

- assessing an authorized repository, SBOM, image reference, or Kubernetes context;
- preparing and reviewing a local remediation proposal;
- opening a bounded dependency-remediation pull request in an explicitly authorized repository;
- rotating a specifically allowlisted machine credential through a typed provider integration;
- verifying that an approved fix is represented by the artifact actually running;
- creating a redacted internal or voluntarily shared receipt;
- contributing non-exploitative detection and verification logic for publicly disclosed incidents.

Prohibited project scope includes:

- exploit or malware generation and distribution;
- credential collection, secret extraction, or persistence;
- scanning public targets without authorization;
- autonomous production deployment, merging, workload changes, or human-password changes;
- response packs that execute arbitrary code or shell commands;
- claims that a receipt proves an entire environment is secure.

Security research contributions must minimize harmful detail and follow coordinated disclosure norms.

