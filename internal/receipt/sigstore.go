package receipt

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"time"

	sigbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"

	"github.com/shubham23596/patchrover/internal/model"
)

const (
	maxReceiptBytes      = 8 << 20
	maxSigstoreBundle    = 8 << 20
	maxSigstoreTrustRoot = 4 << 20
)

// SigstorePolicy binds a receipt to one exact certificate identity and OIDC
// issuer. Exactly one trust-root source must be selected. PublicGood is an
// explicit network opt-in because the Sigstore TUF client may refresh roots.
type SigstorePolicy struct {
	CertificateIdentity   string
	CertificateOIDCIssuer string
	TrustedRootJSON       []byte
	PublicGood            bool
}

// VerifyWithSigstore first verifies the receipt's self-contained DSSE
// integrity, then verifies a standard Sigstore v0.3+ bundle over the exact raw
// receipt file bytes. Identity trust is never inferred from the embedded key.
func VerifyWithSigstore(receiptJSON []byte, receiptBundle model.ReceiptBundle, sigstoreBundleJSON []byte, policy SigstorePolicy) (model.ReceiptVerification, error) {
	verification, err := Verify(receiptBundle)
	if err != nil {
		return model.ReceiptVerification{}, err
	}
	if len(receiptJSON) == 0 || len(receiptJSON) > maxReceiptBytes {
		return model.ReceiptVerification{}, fmt.Errorf("receipt must be between 1 byte and %d bytes", maxReceiptBytes)
	}
	if len(sigstoreBundleJSON) == 0 || len(sigstoreBundleJSON) > maxSigstoreBundle {
		return model.ReceiptVerification{}, fmt.Errorf("Sigstore bundle must be between 1 byte and %d bytes", maxSigstoreBundle)
	}
	if err := validateSigstorePolicy(policy); err != nil {
		return model.ReceiptVerification{}, err
	}
	if verification.Identity != policy.CertificateIdentity {
		return model.ReceiptVerification{}, errors.New("receipt OpenVEX author does not match the required Sigstore certificate identity")
	}

	entity := &sigbundle.Bundle{}
	if err := entity.UnmarshalJSON(sigstoreBundleJSON); err != nil {
		return model.ReceiptVerification{}, fmt.Errorf("decode Sigstore bundle: %w", err)
	}
	if !entity.MinVersion("0.3") {
		return model.ReceiptVerification{}, errors.New("Sigstore bundle v0.3 or newer is required; legacy bundles are not accepted")
	}

	trustedMaterial, err := loadSigstoreTrustedMaterial(policy)
	if err != nil {
		return model.ReceiptVerification{}, err
	}
	if err := verifySigstoreEntity(receiptJSON, entity, trustedMaterial, policy.CertificateIdentity, policy.CertificateOIDCIssuer, true); err != nil {
		return model.ReceiptVerification{}, err
	}

	verification.IdentityTrusted = true
	verification.IdentityIssuer = policy.CertificateOIDCIssuer
	verification.TrustProvider = "sigstore"
	verification.TransparencyVerified = true
	verification.Message = "Receipt integrity and exact Sigstore signer identity are valid; certificate transparency and transparency-log inclusion were verified."
	return verification, nil
}

func validateSigstorePolicy(policy SigstorePolicy) error {
	if policy.CertificateIdentity == "" {
		return errors.New("Sigstore certificate identity is required")
	}
	if policy.CertificateOIDCIssuer == "" {
		return errors.New("Sigstore certificate OIDC issuer is required")
	}
	if len(policy.TrustedRootJSON) > maxSigstoreTrustRoot {
		return fmt.Errorf("Sigstore trusted root exceeds %d bytes", maxSigstoreTrustRoot)
	}
	if policy.PublicGood == (len(policy.TrustedRootJSON) > 0) {
		return errors.New("select exactly one Sigstore trust root: public-good TUF or a trusted-root JSON file")
	}
	return nil
}

func loadSigstoreTrustedMaterial(policy SigstorePolicy) (root.TrustedMaterial, error) {
	if len(policy.TrustedRootJSON) > 0 {
		trustedRoot, err := root.NewTrustedRootFromJSON(policy.TrustedRootJSON)
		if err != nil {
			return nil, fmt.Errorf("decode Sigstore trusted root: %w", err)
		}
		return trustedRoot, nil
	}

	options := tuf.DefaultOptions()
	publicGoodFetcher := fetcher.NewDefaultFetcher()
	publicGoodFetcher.SetHTTPUserAgent("PatchRover Sigstore verifier")
	publicGoodFetcher.SetHTTPClient(&http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(request *http.Request, previous []*http.Request) error {
			if len(previous) >= 3 {
				return errors.New("too many Sigstore TUF redirects")
			}
			if request.URL.Scheme != "https" || request.URL.Hostname() != "tuf-repo-cdn.sigstore.dev" {
				return errors.New("Sigstore TUF redirect left the exact public-good HTTPS host")
			}
			return nil
		},
	})
	options.Fetcher = publicGoodFetcher
	client, err := tuf.New(options)
	if err != nil {
		return nil, fmt.Errorf("initialize Sigstore public-good TUF client: %w", err)
	}
	trustedRoot, err := root.GetTrustedRoot(client)
	if err != nil {
		return nil, fmt.Errorf("load Sigstore public-good trusted root: %w", err)
	}
	return trustedRoot, nil
}

func verifySigstoreEntity(receiptJSON []byte, entity verify.SignedEntity, trustedMaterial root.TrustedMaterial, identity, issuer string, requireSCT bool) error {
	certificateIdentity, err := verify.NewShortCertificateIdentity(issuer, "", identity, "")
	if err != nil {
		return fmt.Errorf("build exact Sigstore identity policy: %w", err)
	}
	options := []verify.VerifierOption{
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	}
	if requireSCT {
		options = append(options, verify.WithSignedCertificateTimestamps(1))
	}
	verifier, err := verify.NewVerifier(trustedMaterial, options...)
	if err != nil {
		return fmt.Errorf("initialize Sigstore verifier: %w", err)
	}
	result, err := verifier.Verify(entity, verify.NewPolicy(
		verify.WithArtifact(bytes.NewReader(receiptJSON)),
		verify.WithCertificateIdentity(certificateIdentity),
	))
	if err != nil {
		return fmt.Errorf("verify Sigstore receipt identity: %w", err)
	}
	if result == nil || result.Signature == nil || result.Signature.Certificate == nil || result.VerifiedIdentity == nil {
		return errors.New("Sigstore verification did not return a certificate-backed identity")
	}
	return nil
}
