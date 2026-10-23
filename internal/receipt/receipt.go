package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/shubham23596/patchrover/internal/model"
	"github.com/shubham23596/patchrover/internal/pack"
)

const (
	bundleMediaType = "application/vnd.patchrover.receipt.bundle+json;version=1"
	payloadType     = "application/vnd.in-toto+json"
	statementType   = "https://in-toto.io/Statement/v1"
	predicateType   = "https://patchrover.dev/attestation/production-receipt/v1"
)

func Create(responsePack model.ResponsePack, trail model.Trail, identity string) (model.ReceiptBundle, error) {
	if trail.Verdict != model.VerdictFixed {
		return model.ReceiptBundle{}, errors.New("a production receipt can be created only for a fixed trail")
	}
	if responsePack.Spec.Verification.RequireRuntimeEvidence && !hasFixedRuntimeFinding(trail) {
		return model.ReceiptBundle{}, errors.New("response pack requires fixed runtime evidence before issuing a receipt")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return model.ReceiptBundle{}, fmt.Errorf("generate ephemeral receipt key: %w", err)
	}
	return CreateWithKey(responsePack, trail, identity, publicKey, privateKey)
}

func CreateWithKey(responsePack model.ResponsePack, trail model.Trail, identity string, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) (model.ReceiptBundle, error) {
	if trail.Verdict != model.VerdictFixed {
		return model.ReceiptBundle{}, errors.New("a production receipt can be created only for a fixed trail")
	}
	if responsePack.Spec.Verification.RequireRuntimeEvidence && !hasFixedRuntimeFinding(trail) {
		return model.ReceiptBundle{}, errors.New("response pack requires fixed runtime evidence before issuing a receipt")
	}
	if len(publicKey) != ed25519.PublicKeySize || len(privateKey) != ed25519.PrivateKeySize {
		return model.ReceiptBundle{}, errors.New("invalid Ed25519 receipt key")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	receiptID := receiptID(trail, now)
	receiptEvidence := redactEvidence(trail.Evidence, receiptID)
	subjects := makeSubjects(receiptEvidence)
	if len(subjects) == 0 {
		return model.ReceiptBundle{}, errors.New("receipt requires at least one SHA-256 artifact digest")
	}
	products := makeProducts(receiptEvidence)
	statements := make([]model.OpenVEXStatement, 0, len(responsePack.Spec.Advisories))
	for _, advisory := range responsePack.Spec.Advisories {
		statements = append(statements, model.OpenVEXStatement{
			Vulnerability: model.OpenVEXVulnerability{Name: advisory.ID},
			Products:      products,
			Status:        "fixed",
			StatusNotes:   "PatchRover observed an explicit fixed artifact and runtime identity under the cited response pack. This is not a claim that the wider environment is secure.",
		})
	}
	statement := model.InTotoStatement{
		Type:          statementType,
		Subject:       subjects,
		PredicateType: predicateType,
		Predicate: model.ReceiptPredicate{
			ReceiptID:       receiptID,
			IssuedAt:        now,
			TrailID:         trail.ID,
			PreviousTrailID: trail.PreviousTrailID,
			PackID:          trail.PackID,
			PackVersion:     trail.PackVersion,
			PackDigest:      trail.PackDigest,
			Verdict:         trail.Verdict,
			OpenVEX: model.OpenVEXDocument{
				Context:    "https://openvex.dev/ns/v0.2.0",
				ID:         "https://patchrover.dev/receipts/" + receiptID + "/openvex",
				Author:     identity,
				Role:       "Document Creator",
				Timestamp:  now,
				Version:    1,
				Tooling:    "PatchRover",
				Statements: statements,
			},
			Evidence: receiptEvidence,
			Limitations: []string{
				"This receipt proves integrity of the included observation, not that the entire environment is secure.",
				"The embedded alpha signing key is self-signed; identity trust requires an external organizational or Sigstore policy.",
				"Repository, cluster, namespace, workload, and pod identifiers are redacted by default.",
			},
		},
	}
	payload, err := json.Marshal(statement)
	if err != nil {
		return model.ReceiptBundle{}, fmt.Errorf("encode in-toto statement: %w", err)
	}
	keyID := pack.PublicKeyID(publicKey)
	signature := ed25519.Sign(privateKey, pae(payloadType, payload))
	return model.ReceiptBundle{
		MediaType: bundleMediaType,
		DSSEEnvelope: model.DSSEEnvelope{
			PayloadType: payloadType,
			Payload:     base64.StdEncoding.EncodeToString(payload),
			Signatures: []model.DSSESignature{{
				KeyID: keyID,
				Sig:   base64.StdEncoding.EncodeToString(signature),
			}},
		},
		VerificationMaterial: model.VerificationMaterial{
			Type:      "ed25519",
			KeyID:     keyID,
			PublicKey: base64.StdEncoding.EncodeToString(publicKey),
			Identity:  identity,
			Trust:     "untrusted-self-signed",
		},
	}, nil
}

func Verify(bundle model.ReceiptBundle) (model.ReceiptVerification, error) {
	if bundle.MediaType != bundleMediaType {
		return model.ReceiptVerification{}, fmt.Errorf("unsupported receipt media type %q", bundle.MediaType)
	}
	if bundle.DSSEEnvelope.PayloadType != payloadType {
		return model.ReceiptVerification{}, fmt.Errorf("unsupported DSSE payload type %q", bundle.DSSEEnvelope.PayloadType)
	}
	if bundle.VerificationMaterial.Type != "ed25519" {
		return model.ReceiptVerification{}, fmt.Errorf("unsupported verification material %q", bundle.VerificationMaterial.Type)
	}
	if bundle.VerificationMaterial.Trust != "untrusted-self-signed" {
		return model.ReceiptVerification{}, errors.New("self-contained Ed25519 receipts cannot assert external identity trust")
	}
	publicKey, err := base64.StdEncoding.DecodeString(bundle.VerificationMaterial.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return model.ReceiptVerification{}, errors.New("invalid receipt public key")
	}
	computedKeyID := pack.PublicKeyID(ed25519.PublicKey(publicKey))
	if computedKeyID != bundle.VerificationMaterial.KeyID {
		return model.ReceiptVerification{}, errors.New("receipt keyId does not match public key")
	}
	payload, err := base64.StdEncoding.DecodeString(bundle.DSSEEnvelope.Payload)
	if err != nil {
		return model.ReceiptVerification{}, errors.New("invalid receipt payload encoding")
	}
	validSignature := false
	for _, signature := range bundle.DSSEEnvelope.Signatures {
		if signature.KeyID != computedKeyID {
			continue
		}
		signatureBytes, err := base64.StdEncoding.DecodeString(signature.Sig)
		if err != nil {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(publicKey), pae(bundle.DSSEEnvelope.PayloadType, payload), signatureBytes) {
			validSignature = true
			break
		}
	}
	if !validSignature {
		return model.ReceiptVerification{}, errors.New("receipt signature verification failed")
	}
	var statement model.InTotoStatement
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&statement); err != nil {
		return model.ReceiptVerification{}, fmt.Errorf("decode signed in-toto statement: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return model.ReceiptVerification{}, errors.New("signed in-toto payload contains trailing JSON values")
	}
	if statement.Type != statementType || statement.PredicateType != predicateType {
		return model.ReceiptVerification{}, errors.New("receipt has an unsupported in-toto statement or predicate type")
	}
	if statement.Predicate.Verdict != model.VerdictFixed {
		return model.ReceiptVerification{}, errors.New("production receipt does not contain a fixed verdict")
	}
	if len(statement.Subject) == 0 || len(statement.Predicate.Evidence) == 0 {
		return model.ReceiptVerification{}, errors.New("production receipt is missing subjects or evidence")
	}
	if statement.Predicate.OpenVEX.Author != bundle.VerificationMaterial.Identity {
		return model.ReceiptVerification{}, errors.New("receipt identity does not match the signed OpenVEX author")
	}
	for _, subject := range statement.Subject {
		if subject.Digest["sha256"] == "" {
			return model.ReceiptVerification{}, errors.New("production receipt subject is missing a SHA-256 digest")
		}
	}
	return model.ReceiptVerification{
		IntegrityValid:  true,
		IdentityTrusted: false,
		Identity:        bundle.VerificationMaterial.Identity,
		ReceiptID:       statement.Predicate.ReceiptID,
		TrailID:         statement.Predicate.TrailID,
		Verdict:         statement.Predicate.Verdict,
		Message:         "Receipt integrity is valid, but signer identity is self-asserted and not trusted by an external policy.",
	}, nil
}

func pae(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

func hasFixedRuntimeFinding(trail model.Trail) bool {
	for _, finding := range trail.Findings {
		if finding.Runtime && finding.Status == model.VerdictFixed {
			return true
		}
	}
	return false
}

func receiptID(trail model.Trail, timestamp string) string {
	sum := sha256.Sum256([]byte(trail.ID + "\x00" + timestamp))
	return "receipt-" + hex.EncodeToString(sum[:10])
}

func redactEvidence(evidence []model.EvidenceRef, salt string) []model.ReceiptEvidence {
	result := make([]model.ReceiptEvidence, 0, len(evidence))
	for _, item := range evidence {
		if item.Digest == "" && item.Version == "" {
			continue
		}
		tokenSource := salt + "\x00" + item.AssetID + "\x00" + item.Location + "\x00" + item.Source
		tokenHash := sha256.Sum256([]byte(tokenSource))
		result = append(result, model.ReceiptEvidence{
			Kind:       item.Kind,
			Name:       item.Name,
			Version:    item.Version,
			Digest:     item.Digest,
			AssetToken: "asset-" + hex.EncodeToString(tokenHash[:8]),
			Runtime:    item.Runtime,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].AssetToken < result[j].AssetToken
	})
	return result
}

func makeSubjects(evidence []model.ReceiptEvidence) []model.InTotoSubject {
	seen := map[string]bool{}
	var subjects []model.InTotoSubject
	for _, item := range evidence {
		if !item.Runtime || !strings.HasPrefix(item.Digest, "sha256:") {
			continue
		}
		digest := strings.TrimPrefix(item.Digest, "sha256:")
		if seen[digest] {
			continue
		}
		seen[digest] = true
		subjects = append(subjects, model.InTotoSubject{
			Name:   item.AssetToken,
			Digest: map[string]string{"sha256": digest},
		})
	}
	return subjects
}

func makeProducts(evidence []model.ReceiptEvidence) []model.OpenVEXProduct {
	products := make([]model.OpenVEXProduct, 0, len(evidence))
	seen := map[string]bool{}
	for _, item := range evidence {
		identifier := "urn:patchrover:" + item.AssetToken
		if seen[identifier] {
			continue
		}
		seen[identifier] = true
		product := model.OpenVEXProduct{ID: identifier}
		if strings.HasPrefix(item.Digest, "sha256:") {
			product.Hashes = map[string]string{"sha-256": strings.TrimPrefix(item.Digest, "sha256:")}
		}
		products = append(products, product)
	}
	return products
}
