package engine

import (
	"path/filepath"
	"testing"

	"github.com/shubham23596/patchrover/internal/collect"
	"github.com/shubham23596/patchrover/internal/model"
	"github.com/shubham23596/patchrover/internal/pack"
)

func TestGoldenCorpusVerdicts(t *testing.T) {
	cases := []struct {
		packID  string
		fixture string
		verdict model.Verdict
		drift   bool
	}{
		{"php-2026-rce", "affected", model.VerdictAffected, false},
		{"php-2026-rce", "fixed", model.VerdictFixed, false},
		{"php-2026-rce", "drift", model.VerdictAffected, true},
		{"php-2026-rce", "unknown", model.VerdictUnknown, false},
		{"litellm-1.107.0-compromise", "affected", model.VerdictAffected, false},
		{"litellm-1.107.0-compromise", "fixed", model.VerdictFixed, false},
		{"litellm-1.107.0-compromise", "drift", model.VerdictAffected, true},
		{"litellm-1.107.0-compromise", "unknown", model.VerdictUnknown, false},
	}
	for _, test := range cases {
		name := test.packID + "/" + test.fixture
		t.Run(name, func(t *testing.T) {
			root := filepath.Join("..", "..", "packs", test.packID)
			responsePack, _, err := pack.LoadFile(root)
			if err != nil {
				t.Fatal(err)
			}
			fixture := filepath.Join(root, "fixtures", test.fixture)
			evidence, err := collect.All(collect.Options{
				RepositoryPath: fixture,
				KubeSnapshot:   filepath.Join(fixture, "pods.json"),
			})
			if err != nil {
				t.Fatal(err)
			}
			trail, err := Assess(responsePack, evidence)
			if err != nil {
				t.Fatal(err)
			}
			if trail.Verdict != test.verdict || trail.Drift != test.drift {
				t.Fatalf("got verdict=%s drift=%t; want verdict=%s drift=%t; findings=%#v", trail.Verdict, trail.Drift, test.verdict, test.drift, trail.Findings)
			}
		})
	}
}

func TestMissingEvidenceIsUnknown(t *testing.T) {
	responsePack, _, err := pack.LoadFile(filepath.Join("..", "..", "packs", "php-2026-rce"))
	if err != nil {
		t.Fatal(err)
	}
	trail, err := Assess(responsePack, nil)
	if err != nil {
		t.Fatal(err)
	}
	if trail.Verdict != model.VerdictUnknown {
		t.Fatalf("missing evidence produced %s, want unknown", trail.Verdict)
	}
}

func TestBarePublishedImageDigestIsAffectedWithoutInferringAName(t *testing.T) {
	responsePack, _, err := pack.LoadFile(filepath.Join("..", "..", "packs", "litellm-1.107.0-compromise"))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := collect.ImageReference("sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e", "operator-image", false)
	if err != nil {
		t.Fatal(err)
	}
	trail, err := Assess(responsePack, []model.EvidenceRef{evidence})
	if err != nil {
		t.Fatal(err)
	}
	if trail.Verdict != model.VerdictAffected || len(trail.Findings) != 1 {
		t.Fatalf("published bare digest did not match safely: %#v", trail)
	}
}

func TestContradictoryEvidenceForSameAssetIsUnknown(t *testing.T) {
	responsePack, _, err := pack.LoadFile(filepath.Join("..", "..", "packs", "php-2026-rce"))
	if err != nil {
		t.Fatal(err)
	}
	evidence := []model.EvidenceRef{
		{ID: "ev-affected", Source: "operator", AssetID: "runtime/api", Kind: "runtime", Name: "php", Version: "8.4.26", Runtime: true},
		{ID: "ev-fixed", Source: "operator", AssetID: "runtime/api", Kind: "runtime", Name: "php", Version: "8.4.27", Runtime: true},
	}
	trail, err := Assess(responsePack, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if trail.Verdict != model.VerdictUnknown || trail.Drift {
		t.Fatalf("contradictory evidence produced verdict=%s drift=%t, want unknown without drift", trail.Verdict, trail.Drift)
	}
}

func TestTrailTamperingFailsValidation(t *testing.T) {
	responsePack, _, err := pack.LoadFile(filepath.Join("..", "..", "packs", "php-2026-rce"))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := collect.All(collect.Options{RepositoryPath: filepath.Join("..", "..", "packs", "php-2026-rce", "fixtures", "affected")})
	if err != nil {
		t.Fatal(err)
	}
	trail, err := Assess(responsePack, evidence)
	if err != nil {
		t.Fatal(err)
	}
	trail.Verdict = model.VerdictFixed
	if err := ValidateTrail(responsePack, trail); err == nil {
		t.Fatal("tampered verdict unexpectedly validated")
	}
	trail, err = Assess(responsePack, evidence)
	if err != nil {
		t.Fatal(err)
	}
	trail.Evidence[0].Version = "8.4.27-apache"
	if err := ValidateTrail(responsePack, trail); err == nil {
		t.Fatal("tampered evidence unexpectedly validated")
	}
	trail, err = Assess(responsePack, evidence)
	if err != nil {
		t.Fatal(err)
	}
	trail.PreviousTrailID = "trail-forged"
	if err := ValidateTrail(responsePack, trail); err == nil {
		t.Fatal("tampered chain link unexpectedly validated")
	}
}
