## What changed

Describe the user-visible and trust-boundary impact.

## Evidence

- [ ] `go test -race ./...`
- [ ] `go vet ./...`
- [ ] `go run ./cmd/patchrover demo`
- [ ] Both published packs validate
- [ ] `cd site && npm ci && npm run build` (when the site changed)

## Security checklist

- [ ] Missing or contradictory evidence still returns `unknown`.
- [ ] No pack-controlled command, network access, credential access, or production write was introduced.
- [ ] New fixtures are synthetic and contain no vulnerable artifact, secret, exploit, or customer identifier.
- [ ] The change has a DCO `Signed-off-by` line.
