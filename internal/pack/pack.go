package pack

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/shubham23596/patchrover/internal/model"
)

var packIDPattern = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)

const (
	registryKeyID     = "sha256:cb13b1803f8e5cb8021b6af28a0431e2"
	registryPublicKey = "0zAgcQXNocbHiGccXn3iRbJc1ITd/HY+3VgsxyzmliY="
)

type Validation struct {
	PackDigest string
	KeyID      string
	Trust      string
	Warnings   []string
}

func LoadFile(path string) (model.ResponsePack, Validation, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return model.ResponsePack{}, Validation{}, fmt.Errorf("inspect response-pack path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return model.ResponsePack{}, Validation{}, errors.New("response-pack path must not be a symlink")
	}
	if info.IsDir() {
		path = path + string(os.PathSeparator) + "pack.json"
		info, err = os.Lstat(path)
		if err != nil {
			return model.ResponsePack{}, Validation{}, fmt.Errorf("inspect response-pack file: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return model.ResponsePack{}, Validation{}, errors.New("response-pack file must not be a symlink")
		}
	}
	if !info.Mode().IsRegular() {
		return model.ResponsePack{}, Validation{}, errors.New("response-pack path must resolve to a regular JSON file")
	}
	if info.Size() > 4<<20 {
		return model.ResponsePack{}, Validation{}, errors.New("response-pack file exceeds the 4 MiB safety limit")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return model.ResponsePack{}, Validation{}, fmt.Errorf("read response pack: %w", err)
	}
	return Load(data)
}

func Load(data []byte) (model.ResponsePack, Validation, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var responsePack model.ResponsePack
	if err := decoder.Decode(&responsePack); err != nil {
		return model.ResponsePack{}, Validation{}, fmt.Errorf("decode response pack: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return model.ResponsePack{}, Validation{}, errors.New("response pack contains trailing JSON values")
	}
	validation, err := Validate(responsePack, time.Now().UTC())
	if err != nil {
		return model.ResponsePack{}, Validation{}, err
	}
	return responsePack, validation, nil
}

func Validate(responsePack model.ResponsePack, now time.Time) (Validation, error) {
	if responsePack.APIVersion != model.APIVersion {
		return Validation{}, fmt.Errorf("unsupported apiVersion %q", responsePack.APIVersion)
	}
	if responsePack.Kind != model.PackKind {
		return Validation{}, fmt.Errorf("unsupported kind %q", responsePack.Kind)
	}
	if !packIDPattern.MatchString(responsePack.Metadata.ID) {
		return Validation{}, fmt.Errorf("invalid metadata.id %q", responsePack.Metadata.ID)
	}
	if strings.TrimSpace(responsePack.Metadata.Version) == "" || strings.TrimSpace(responsePack.Metadata.Title) == "" || strings.TrimSpace(responsePack.Metadata.Summary) == "" || strings.TrimSpace(responsePack.Metadata.Author) == "" {
		return Validation{}, errors.New("metadata.version, title, summary, and author are required")
	}
	switch responsePack.Metadata.ReviewState {
	case "provisional", "verified":
	case "revoked":
		return Validation{}, errors.New("response pack is revoked")
	default:
		return Validation{}, fmt.Errorf("unsupported reviewState %q", responsePack.Metadata.ReviewState)
	}
	publishedAt, err := time.Parse(time.RFC3339, responsePack.Metadata.PublishedAt)
	if err != nil {
		return Validation{}, fmt.Errorf("invalid metadata.publishedAt: %w", err)
	}
	if publishedAt.After(now.Add(5 * time.Minute)) {
		return Validation{}, errors.New("metadata.publishedAt is in the future")
	}
	expiresAt, err := time.Parse(time.RFC3339, responsePack.Metadata.ExpiresAt)
	if err != nil {
		return Validation{}, fmt.Errorf("invalid metadata.expiresAt: %w", err)
	}
	if !expiresAt.After(publishedAt) {
		return Validation{}, errors.New("metadata.expiresAt must be after metadata.publishedAt")
	}
	if !expiresAt.After(now) {
		return Validation{}, errors.New("response pack is expired")
	}
	if len(responsePack.Spec.Advisories) == 0 || len(responsePack.Spec.Sources) == 0 || len(responsePack.Spec.Matchers) == 0 {
		return Validation{}, errors.New("advisories, sources, and matchers must not be empty")
	}
	seenAdvisories := map[string]bool{}
	for _, advisory := range responsePack.Spec.Advisories {
		if strings.TrimSpace(advisory.ID) == "" || strings.TrimSpace(advisory.Severity) == "" {
			return Validation{}, errors.New("every advisory requires id and severity")
		}
		if seenAdvisories[advisory.ID] {
			return Validation{}, fmt.Errorf("duplicate advisory id %q", advisory.ID)
		}
		seenAdvisories[advisory.ID] = true
	}
	seenSources := map[string]bool{}
	for _, source := range responsePack.Spec.Sources {
		if strings.TrimSpace(source.Title) == "" {
			return Validation{}, errors.New("every pack source requires a title")
		}
		parsed, err := url.Parse(source.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return Validation{}, fmt.Errorf("pack source must be an absolute HTTPS URL: %q", source.URL)
		}
		if seenSources[source.URL] {
			return Validation{}, fmt.Errorf("duplicate pack source %q", source.URL)
		}
		seenSources[source.URL] = true
	}
	seenMatcherIDs := map[string]bool{}
	for _, matcher := range responsePack.Spec.Matchers {
		if matcher.ID == "" || matcher.Name == "" || len(matcher.ArtifactKinds) == 0 {
			return Validation{}, errors.New("every matcher requires id, name, and artifactKinds")
		}
		if seenMatcherIDs[matcher.ID] {
			return Validation{}, fmt.Errorf("duplicate matcher id %q", matcher.ID)
		}
		seenMatcherIDs[matcher.ID] = true
		if len(matcher.AffectedVersions) == 0 && len(matcher.AffectedVersionRanges) == 0 && len(matcher.AffectedDigests) == 0 {
			return Validation{}, fmt.Errorf("matcher %q has no affected rule", matcher.ID)
		}
		if len(matcher.FixedVersions) == 0 && len(matcher.MinimumFixedVersions) == 0 {
			return Validation{}, fmt.Errorf("matcher %q has no fixed rule", matcher.ID)
		}
	}
	if strings.TrimSpace(responsePack.Spec.Remediation.Summary) == "" || len(responsePack.Spec.Remediation.Steps) == 0 {
		return Validation{}, errors.New("remediation summary and steps are required")
	}
	if len(responsePack.Spec.Verification.Requirements) == 0 {
		return Validation{}, errors.New("verification requirements must not be empty")
	}
	if responsePack.Signature == nil {
		return Validation{}, errors.New("response pack is unsigned")
	}
	keyID, err := verifySignature(responsePack)
	if err != nil {
		return Validation{}, err
	}
	digest, err := responsePack.Digest()
	if err != nil {
		return Validation{}, fmt.Errorf("compute response pack digest: %w", err)
	}
	trust := "untrusted-self-signed"
	if keyID == registryKeyID && responsePack.Signature.PublicKey == registryPublicKey {
		trust = "patchrover-registry-v1"
	}
	warnings := []string{}
	if responsePack.Metadata.ReviewState == "provisional" {
		warnings = append(warnings, "pack is provisional and may change as the incident investigation evolves")
	}
	if expiresAt.Sub(now) < 14*24*time.Hour {
		warnings = append(warnings, "pack expires in less than 14 days")
	}
	return Validation{PackDigest: digest, KeyID: keyID, Trust: trust, Warnings: warnings}, nil
}

func RequireTrusted(validation Validation) error {
	if validation.Trust != "patchrover-registry-v1" {
		return fmt.Errorf("response-pack signer %s is not in the trusted registry key set", validation.KeyID)
	}
	return nil
}

func Sign(responsePack model.ResponsePack, privateKey ed25519.PrivateKey) (model.ResponsePack, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return model.ResponsePack{}, errors.New("invalid Ed25519 private key")
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID := PublicKeyID(publicKey)
	responsePack.Signature = nil
	data, err := responsePack.CanonicalBytes()
	if err != nil {
		return model.ResponsePack{}, err
	}
	signature := ed25519.Sign(privateKey, data)
	responsePack.Signature = &model.PackSignature{
		Algorithm: "ed25519",
		KeyID:     keyID,
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		Value:     base64.StdEncoding.EncodeToString(signature),
	}
	return responsePack, nil
}

func verifySignature(responsePack model.ResponsePack) (string, error) {
	signature := responsePack.Signature
	if signature.Algorithm != "ed25519" {
		return "", fmt.Errorf("unsupported signature algorithm %q", signature.Algorithm)
	}
	publicKey, err := base64.StdEncoding.DecodeString(signature.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return "", errors.New("invalid response-pack public key")
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(signature.Value)
	if err != nil || len(signatureBytes) != ed25519.SignatureSize {
		return "", errors.New("invalid response-pack signature encoding")
	}
	computedKeyID := PublicKeyID(ed25519.PublicKey(publicKey))
	if signature.KeyID != computedKeyID {
		return "", errors.New("response-pack keyId does not match public key")
	}
	canonical, err := responsePack.CanonicalBytes()
	if err != nil {
		return "", fmt.Errorf("canonicalize response pack: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), canonical, signatureBytes) {
		return "", errors.New("response-pack signature verification failed")
	}
	return computedKeyID, nil
}

func PublicKeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(sum[:16])
}
