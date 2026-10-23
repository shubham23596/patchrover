# Contributing

Thank you for helping defenders respond faster.

## Development

Requirements:

- Go 1.27 or newer.
- Node.js 24 and npm for the website.

Run:

```bash
make verify
make build packs
cd site && npm ci && npm run check && npm run build
```

## Response-pack contributions

Packs must:

- cite authoritative HTTPS sources;
- use synthetic fixtures only;
- include affected, fixed, deployment-drift, and insufficient-evidence fixtures, with contradiction tests when multiple observations can identify the same asset;
- return `unknown` rather than guessing;
- avoid exploit steps, malware, credentials, or arbitrary execution;
- specify expiry and review state;
- pass `patchrover pack validate`;
- receive two security-maintainer approvals before `verified` status.

Community pull requests can omit a production registry signature during review only on a dedicated contribution branch. The merge process signs the reviewed canonical pack. Bundled release packs must always be signed.

## Developer Certificate of Origin

Every commit must include a `Signed-off-by` line certifying the Developer Certificate of Origin 1.1:

```bash
git commit -s -m "Describe the change"
```

By signing off, you certify that you have the right to submit the work under the project's Apache-2.0 license.

## Security-sensitive changes

Do not open a public pull request for a vulnerability that would expose users before a fix exists. Follow [SECURITY.md](SECURITY.md).

