# Public Launch Checklist

The repository is deliberately launch-gated. Do not set the enablement variables until every owner has reviewed this list.

## 1. Name and company ownership

- Complete trademark, Singapore corporate-name, domain, GitHub, Go module, package-registry, and social-handle clearance for **PatchRover**.
- If clearance fails, use the predetermined fallback **AttestHound** only after running the same clearance process.
- Register any future domain, trademark applications, release identities, and cloud accounts to the Singapore company. The alpha source repository may remain under founder account `shubham23596`.
- Add the founder’s personal GitHub account as visibly attributed founder and lead maintainer.

## 2. GitHub repository

- Create `shubham23596/patchrover` from the founder's personal GitHub login.
- Add a second trusted repository administrator before a stable production release.
- Require secure two-factor authentication or passkeys for every administrator and release maintainer.
- Create the `security-maintainers` team referenced by `CODEOWNERS`; grant only the minimum necessary permissions.
- Create the repository privately, preserve the `main` branch, verify contribution attribution, run all launch checks, and then make the alpha repository public.
- Set default Actions permissions to read-only and disable approval of pull requests by workflows.
- Enable secret scanning, push protection, dependency graph, Dependabot alerts, CodeQL, and private vulnerability reporting where the account plan supports them.

## 3. Branches, tags, and releases

- Protect `main`: pull requests required, stale approvals dismissed, conversation resolution required, signed commits evaluated, and CI/CodeQL/DCO checks required.
- Require two `security-maintainers` approvals for `packs/`, trust-root, receipt, and workflow changes.
- Protect release tags matching `v*` and restrict creation to release maintainers.
- Create a protected `release` environment with at least one independent approver.
- Enable immutable releases in repository settings.
- Confirm the `patchrover-registry-v1` public trust root and both re-signed packs match the device-bound company maintainer key; establish independent recovery or keyless rotation before adding another signer.
- Set repository variable `RELEASES_ENABLED=true` only after these controls work on a private release candidate.

## 4. Website and contact

- Configure a monitored company security address and a separate design-partner address.
- Set `PUBLIC_CONTACT_EMAIL` to the design-partner address; keep private reports on GitHub private vulnerability reporting or the monitored security address.
- Set `PUBLIC_SITE_URL` after domain/DNS approval, or leave it blank for the GitHub Pages URL.
- Set `PUBLIC_LAUNCH=true` only when the source repository is public and the launch page is accurate.
- Configure and verify the GitHub Pages custom domain and HTTPS enforcement.
- Re-run Lighthouse on the production URL; require performance, accessibility, best-practices, and SEO scores of at least 95.

## 5. Final evidence

- Run `make verify`, `make build packs demo`, `cd site && npm ci && npm run build && npm run lighthouse`.
- Confirm the disposable OCI/Kubernetes CI job passes on `main`.
- Review the two packs against their latest authoritative sources; update, expire, or revoke changed content.
- Confirm pack, trail, and receipt tamper tests fail closed and default receipts contain no internal identifiers.
- Test binaries on macOS and Linux, both x86-64 and ARM64.
- Have an external security engineer run the demo and review the threat model before the repository becomes public.

No DigitalOcean resource, domain, paid model, API, or other paid service should be purchased without a current exact-cost estimate and explicit approval.
