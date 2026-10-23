package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"

	"github.com/shubham23596/patchrover/internal/model"
)

func TestReceiptIntegrityRedactionAndTamperDetection(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	responsePack := model.ResponsePack{
		Spec: model.PackSpec{
			Advisories:   []model.Advisory{{ID: "CVE-TEST-1", Severity: "critical"}},
			Verification: model.VerificationRules{RequireRuntimeEvidence: true},
		},
	}
	trail := model.Trail{
		ID: "trail-test", PackID: "test-pack", PackVersion: "1", PackDigest: "sha256:pack", Verdict: model.VerdictFixed,
		Evidence: []model.EvidenceRef{{
			ID: "ev-1", AssetID: "secret-cluster/secret-namespace/secret-pod", Source: "secret-source", Location: "secret-repo/path", Kind: "oci-image", Name: "app", Version: "1.2.3", Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Runtime: true,
		}},
		Findings: []model.Finding{{EvidenceID: "ev-1", Status: model.VerdictFixed, Runtime: true}},
	}
	bundle, err := CreateWithKey(responsePack, trail, "security@example.invalid", publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := Verify(bundle)
	if err != nil || !verification.IntegrityValid || verification.IdentityTrusted {
		t.Fatalf("unexpected verification: %#v err=%v", verification, err)
	}
	payload, err := base64.StdEncoding.DecodeString(bundle.DSSEEnvelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-cluster", "secret-namespace", "secret-pod", "secret-repo", "secret-source"} {
		if strings.Contains(string(payload), secret) {
			t.Fatalf("receipt leaked internal identifier %q", secret)
		}
	}
	bundle.DSSEEnvelope.Payload = base64.StdEncoding.EncodeToString(append(payload, byte(' ')))
	if _, err := Verify(bundle); err == nil {
		t.Fatal("tampered receipt unexpectedly verified")
	}
}

func TestSelfSignedReceiptCannotClaimExternalTrust(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	responsePack := model.ResponsePack{Spec: model.PackSpec{Advisories: []model.Advisory{{ID: "CVE-TEST-1"}}}}
	trail := model.Trail{
		ID: "trail-test", Verdict: model.VerdictFixed,
		Evidence: []model.EvidenceRef{{Name: "app", Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Runtime: true}},
		Findings: []model.Finding{{Status: model.VerdictFixed, Runtime: true}},
	}
	bundle, err := CreateWithKey(responsePack, trail, "self@example.invalid", publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle.VerificationMaterial.Trust = "organization-trusted"
	if _, err := Verify(bundle); err == nil {
		t.Fatal("self-signed receipt unexpectedly asserted organization trust")
	}
}

func TestReceiptRejectsNonFixedTrail(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	responsePack := model.ResponsePack{Spec: model.PackSpec{Verification: model.VerificationRules{}}}
	if _, err := CreateWithKey(responsePack, model.Trail{Verdict: model.VerdictAffected}, "test", publicKey, privateKey); err == nil {
		t.Fatal("affected trail unexpectedly produced a receipt")
	}
}

func TestSigstoreIdentityPolicyBindsExactArtifactIdentityAndIssuer(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	receiptJSON := []byte(`{"receipt":"exact bytes"}`)
	identity := "security@patchrover.example"
	issuer := "https://issuer.patchrover.example"
	entity, err := virtualSigstore.Sign(identity, issuer, receiptJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySigstoreEntity(receiptJSON, entity, virtualSigstore, identity, issuer, false); err != nil {
		t.Fatalf("valid Sigstore identity failed: %v", err)
	}
	if err := verifySigstoreEntity([]byte(`{"receipt":"changed bytes"}`), entity, virtualSigstore, identity, issuer, false); err == nil {
		t.Fatal("Sigstore bundle unexpectedly verified different receipt bytes")
	}
	if err := verifySigstoreEntity(receiptJSON, entity, virtualSigstore, "other@patchrover.example", issuer, false); err == nil {
		t.Fatal("Sigstore bundle unexpectedly verified a different identity")
	}
	if err := verifySigstoreEntity(receiptJSON, entity, virtualSigstore, identity, "https://other-issuer.example", false); err == nil {
		t.Fatal("Sigstore bundle unexpectedly verified a different issuer")
	}
}

func TestSigstorePolicyRequiresOneExplicitTrustRoot(t *testing.T) {
	base := SigstorePolicy{CertificateIdentity: "security@patchrover.example", CertificateOIDCIssuer: "https://issuer.example"}
	if err := validateSigstorePolicy(base); err == nil {
		t.Fatal("Sigstore policy unexpectedly accepted no trust root")
	}
	both := base
	both.PublicGood = true
	both.TrustedRootJSON = []byte(`{}`)
	if err := validateSigstorePolicy(both); err == nil {
		t.Fatal("Sigstore policy unexpectedly accepted two trust roots")
	}
	publicGood := base
	publicGood.PublicGood = true
	if err := validateSigstorePolicy(publicGood); err != nil {
		t.Fatalf("explicit public-good trust root rejected: %v", err)
	}
}

func TestLiveSigstorePublicGoodTrustedRoot(t *testing.T) {
	if os.Getenv("PATCHROVER_LIVE_SIGSTORE_TUF") != "1" {
		t.Skip("set PATCHROVER_LIVE_SIGSTORE_TUF=1 for the explicit network integration test")
	}
	trustedMaterial, err := loadSigstoreTrustedMaterial(SigstorePolicy{
		CertificateIdentity:   "integration-test@patchrover.invalid",
		CertificateOIDCIssuer: "https://issuer.patchrover.invalid",
		PublicGood:            true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(trustedMaterial.FulcioCertificateAuthorities()) == 0 || len(trustedMaterial.RekorLogs()) == 0 || len(trustedMaterial.CTLogs()) == 0 {
		t.Fatal("Sigstore public-good trusted root is missing Fulcio, Rekor, or CT material")
	}
}
