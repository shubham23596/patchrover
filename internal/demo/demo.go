package demo

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/shubham23596/patchrover/internal/collect"
	"github.com/shubham23596/patchrover/internal/engine"
	"github.com/shubham23596/patchrover/internal/model"
	"github.com/shubham23596/patchrover/internal/pack"
	"github.com/shubham23596/patchrover/internal/proposal"
	"github.com/shubham23596/patchrover/internal/receipt"
)

const (
	affectedDigest = "sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e"
	fixedDigest    = "sha256:4d48c2d49a7e179b6cf2af4c11b2e64cb0f1a65ff6299c2ce458af278c4fd22a"
)

func Run(output io.Writer) error {
	workspace, err := os.MkdirTemp("", "patchrover-demo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workspace)
	beforeRepo := filepath.Join(workspace, "before")
	afterRepo := filepath.Join(workspace, "after")
	if err := os.MkdirAll(beforeRepo, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(afterRepo, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(beforeRepo, "requirements.txt"), []byte("fastapi==0.120.0\nlitellm==1.107.0\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(afterRepo, "requirements.txt"), []byte("fastapi==0.120.0\nlitellm==1.106.2\n"), 0o600); err != nil {
		return err
	}
	affectedSnapshot := filepath.Join(workspace, "affected-pods.json")
	fixedSnapshot := filepath.Join(workspace, "fixed-pods.json")
	if err := os.WriteFile(affectedSnapshot, kubeSnapshot("litellm:v1.107.0", affectedDigest), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(fixedSnapshot, kubeSnapshot("litellm:v1.106.2", fixedDigest), 0o600); err != nil {
		return err
	}
	demoPack, err := signedDemoPack()
	if err != nil {
		return err
	}
	validation, err := pack.Validate(demoPack, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("validate demo response pack: %w", err)
	}
	fmt.Fprintln(output, "PatchRover demo — Track. Fix. Prove.")
	fmt.Fprintln(output, "Synthetic fixtures only. No account, network, model, vulnerable package, or production write is used.")
	fmt.Fprintf(output, "\n1/5  Verified signed response pack  %s\n", validation.PackDigest)

	affectedEvidence, err := collect.All(collect.Options{RepositoryPath: beforeRepo, KubeSnapshot: affectedSnapshot})
	if err != nil {
		return err
	}
	affectedTrail, err := engine.Assess(demoPack, affectedEvidence)
	if err != nil {
		return err
	}
	if affectedTrail.Verdict != model.VerdictAffected {
		return fmt.Errorf("expected affected demo trail, got %s", affectedTrail.Verdict)
	}
	fmt.Fprintf(output, "2/5  ASSESS  %-9s  source version and running digest match the incident pack\n", affectedTrail.Verdict)

	remediation := proposal.Build(demoPack, affectedTrail, beforeRepo)
	if len(remediation.Changes) == 0 {
		return fmt.Errorf("demo did not produce a safe local proposal")
	}
	fmt.Fprintf(output, "3/5  PROPOSE local diff only  %s → %s\n", remediation.Changes[0].OldVersion, remediation.Changes[0].NewVersion)
	fmt.Fprintln(output, "     Human approval and deployment are intentionally outside PatchRover v1.")

	fixedEvidence, err := collect.All(collect.Options{RepositoryPath: afterRepo, KubeSnapshot: fixedSnapshot})
	if err != nil {
		return err
	}
	fixedTrail, err := engine.Assess(demoPack, fixedEvidence)
	if err != nil {
		return err
	}
	if fixedTrail.Verdict != model.VerdictFixed {
		return fmt.Errorf("expected fixed demo trail, got %s", fixedTrail.Verdict)
	}
	fixedTrail, err = engine.LinkPrevious(demoPack, fixedTrail, affectedTrail.ID)
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "4/5  VERIFY  %-9s  fixed source and running image digest observed\n", fixedTrail.Verdict)

	receiptBundle, err := receipt.Create(demoPack, fixedTrail, "patchrover-demo@local")
	if err != nil {
		return err
	}
	verification, err := receipt.Verify(receiptBundle)
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "5/5  RECEIPT integrity=%t identityTrusted=%t\n", verification.IntegrityValid, verification.IdentityTrusted)
	fmt.Fprintln(output, "     Expected alpha limitation: the ephemeral demo signer proves integrity, not organizational identity.")
	fmt.Fprintln(output, "\nDemo complete. A real run would retain the trail, reviewed proposal, and receipt locally.")
	return nil
}

func signedDemoPack() (model.ResponsePack, error) {
	responsePack := model.ResponsePack{
		APIVersion: model.APIVersion,
		Kind:       model.PackKind,
		Metadata: model.PackMetadata{
			ID:          "litellm-demo-compromise",
			Version:     "1.0.0-demo",
			Title:       "Synthetic LiteLLM compromise demo",
			Summary:     "Safe synthetic reproduction of version and runtime-digest evidence.",
			Author:      "PatchRover demo",
			ReviewState: "verified",
			PublishedAt: "2026-10-21T20:30:00Z",
			ExpiresAt:   "2027-01-21T20:30:00Z",
		},
		Spec: model.PackSpec{
			Advisories: []model.Advisory{{ID: "INCIDENT-LITELLM-2026-10-21", Severity: "critical"}},
			Sources:    []model.PackSource{{Title: "LiteLLM incident report", URL: "https://docs.litellm.ai/blog/security-incident-oct-21-2026"}},
			Matchers: []model.Matcher{{
				ID:               "litellm-artifact",
				ArtifactKinds:    []string{"python-package", "oci-image"},
				Name:             "litellm",
				AffectedVersions: []string{"1.107.0", "v1.107.0"},
				FixedVersions:    []string{"1.106.2", "v1.106.2"},
				AffectedDigests:  []string{affectedDigest},
				Notes:            "Demo rules mirror public metadata but never include or execute the compromised artifact.",
			}},
			Remediation: model.Remediation{
				Summary:              "Rebuild from a known-safe dependency and image, then rotate reachable credentials.",
				Steps:                []string{"Remove the affected artifact without starting Python in the affected environment.", "Rebuild from clean inputs pinned to a known-safe version.", "Deploy only after human review."},
				Tests:                []string{"Run the application test suite in an isolated clean environment."},
				OperationalChecks:    []string{"Verify the running workload image digest after deployment."},
				RequiredApprovals:    []string{"Application owner", "Security incident owner"},
				CredentialRotation:   []string{"Rotate every credential reachable from an environment that ran the affected artifact."},
				CompromiseAssumption: "If the affected artifact executed with outbound access, assume reachable credentials may be compromised.",
			},
			Verification: model.VerificationRules{
				RequireRuntimeEvidence: true,
				Requirements:           []string{"Observe a fixed source pin.", "Observe a non-affected running image digest."},
			},
		},
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return model.ResponsePack{}, err
	}
	return pack.Sign(responsePack, privateKey)
}

func kubeSnapshot(image, digest string) []byte {
	document := map[string]any{
		"apiVersion": "v1",
		"kind":       "PodList",
		"items": []any{map[string]any{
			"metadata": map[string]any{"namespace": "synthetic-demo", "name": "gateway-0"},
			"spec":     map[string]any{"containers": []any{map[string]any{"name": "gateway", "image": image}}},
			"status": map[string]any{"containerStatuses": []any{map[string]any{
				"name":    "gateway",
				"image":   image,
				"imageID": "docker-pullable://example.invalid/litellm@" + digest,
			}}},
		}},
	}
	data, _ := json.Marshal(document)
	return data
}
