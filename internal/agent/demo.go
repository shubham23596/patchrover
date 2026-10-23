package agent

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/shubham23596/patchrover/internal/collect"
	"github.com/shubham23596/patchrover/internal/engine"
	"github.com/shubham23596/patchrover/internal/model"
	"github.com/shubham23596/patchrover/internal/proposal"
)

// Demo exercises the autonomous decision and bounded-edit path without network
// access, provider credentials, or external mutations.
func Demo(output io.Writer) error {
	workspace, err := os.MkdirTemp("", "patchrover-agent-demo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workspace)
	content := []byte("litellm==1.107.0\n")
	if err := os.WriteFile(filepath.Join(workspace, "requirements.txt"), content, 0o600); err != nil {
		return err
	}
	responsePack := model.ResponsePack{
		APIVersion: model.APIVersion, Kind: model.PackKind,
		Metadata: model.PackMetadata{ID: "synthetic-agent-demo", Version: "1", Title: "Synthetic agent demo", Summary: "Offline demo", Author: "PatchRover", ReviewState: "verified", PublishedAt: "2026-01-01T00:00:00Z", ExpiresAt: "2027-01-01T00:00:00Z"},
		Spec: model.PackSpec{
			Advisories:   []model.Advisory{{ID: "SYNTHETIC-1", Severity: "critical"}},
			Sources:      []model.PackSource{{Title: "Synthetic offline source", URL: "https://example.invalid/advisory"}},
			Matchers:     []model.Matcher{{ID: "litellm", ArtifactKinds: []string{"python-package"}, Name: "litellm", AffectedVersions: []string{"1.107.0"}, FixedVersions: []string{"1.106.2"}}},
			Remediation:  model.Remediation{Summary: "Use the known-safe synthetic version.", Steps: []string{"Open a bounded pull request."}, CredentialRotation: []string{"Rotate explicitly authorized machine credentials."}},
			Verification: model.VerificationRules{Requirements: []string{"Reassess source and runtime."}},
		},
	}
	evidence, err := collect.Repository(workspace)
	if err != nil {
		return err
	}
	trail, err := engine.Assess(responsePack, evidence)
	if err != nil {
		return err
	}
	remediation := proposal.Build(responsePack, trail, workspace)
	if trail.Verdict != model.VerdictAffected || len(remediation.Changes) != 1 {
		return fmt.Errorf("synthetic agent demo did not produce one bounded remediation")
	}
	updated, err := proposal.ApplyChange(content, remediation.Changes[0])
	if err != nil {
		return err
	}
	fmt.Fprintln(output, "PatchRover autonomous agent demo — offline and mutation-free")
	fmt.Fprintln(output, "1/4  MONITOR    synthetic authoritative advisory observed")
	fmt.Fprintf(output, "2/4  CORRELATE  %s from deterministic evidence\n", trail.Verdict)
	fmt.Fprintf(output, "3/4  REMEDIATE  bounded PR content prepared: %s", updated)
	fmt.Fprintln(output, "4/4  POLICY     repository PR and machine-credential rotation require explicit allowlists")
	fmt.Fprintln(output, "No network, token, password, repository, or production system was changed.")
	return nil
}
