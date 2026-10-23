package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

const (
	APIVersion = "patchrover.dev/v1alpha1"
	PackKind   = "ResponsePack"
)

type Verdict string

const (
	VerdictAffected    Verdict = "affected"
	VerdictFixed       Verdict = "fixed"
	VerdictNotAffected Verdict = "not_affected"
	VerdictUnknown     Verdict = "unknown"
)

type ResponsePack struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Metadata   PackMetadata   `json:"metadata"`
	Spec       PackSpec       `json:"spec"`
	Signature  *PackSignature `json:"signature,omitempty"`
}

type PackMetadata struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	Title       string `json:"title"`
	Summary     string `json:"summary"`
	Author      string `json:"author"`
	ReviewState string `json:"reviewState"`
	PublishedAt string `json:"publishedAt"`
	ExpiresAt   string `json:"expiresAt"`
}

type PackSpec struct {
	Advisories   []Advisory        `json:"advisories"`
	Sources      []PackSource      `json:"sources"`
	Matchers     []Matcher         `json:"matchers"`
	Remediation  Remediation       `json:"remediation"`
	Verification VerificationRules `json:"verification"`
}

type Advisory struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
}

type PackSource struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

type Matcher struct {
	ID                    string           `json:"id"`
	ArtifactKinds         []string         `json:"artifactKinds"`
	Name                  string           `json:"name"`
	AffectedVersions      []string         `json:"affectedVersions,omitempty"`
	AffectedVersionRanges []VersionRange   `json:"affectedVersionRanges,omitempty"`
	FixedVersions         []string         `json:"fixedVersions,omitempty"`
	MinimumFixedVersions  []VersionMinimum `json:"minimumFixedVersions,omitempty"`
	AffectedDigests       []string         `json:"affectedDigests,omitempty"`
	Notes                 string           `json:"notes"`
}

type VersionRange struct {
	Line     string `json:"line"`
	LessThan string `json:"lessThan"`
}

type VersionMinimum struct {
	Line    string `json:"line"`
	Version string `json:"version"`
}

type Remediation struct {
	Summary              string   `json:"summary"`
	Steps                []string `json:"steps"`
	Tests                []string `json:"tests"`
	OperationalChecks    []string `json:"operationalChecks"`
	RequiredApprovals    []string `json:"requiredApprovals"`
	CredentialRotation   []string `json:"credentialRotation,omitempty"`
	CompromiseAssumption string   `json:"compromiseAssumption,omitempty"`
}

type VerificationRules struct {
	RequireRuntimeEvidence bool     `json:"requireRuntimeEvidence"`
	Requirements           []string `json:"requirements"`
}

type PackSignature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"keyId"`
	PublicKey string `json:"publicKey"`
	Value     string `json:"value"`
}

func (p ResponsePack) CanonicalBytes() ([]byte, error) {
	p.Signature = nil
	return json.Marshal(p)
}

func (p ResponsePack) Digest() (string, error) {
	data, err := p.CanonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

type EvidenceRef struct {
	ID         string `json:"id"`
	Source     string `json:"source"`
	ObservedAt string `json:"observedAt"`
	AssetID    string `json:"assetId"`
	Collector  string `json:"collector"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Digest     string `json:"digest,omitempty"`
	Location   string `json:"location,omitempty"`
	Runtime    bool   `json:"runtime"`
	Confidence string `json:"confidence"`
	Detail     string `json:"detail"`
}

type Finding struct {
	MatcherID  string  `json:"matcherId"`
	EvidenceID string  `json:"evidenceId"`
	Status     Verdict `json:"status"`
	Reason     string  `json:"reason"`
	Runtime    bool    `json:"runtime"`
}

type Trail struct {
	APIVersion      string        `json:"apiVersion"`
	Kind            string        `json:"kind"`
	ID              string        `json:"id"`
	PreviousTrailID string        `json:"previousTrailId,omitempty"`
	PackID          string        `json:"packId"`
	PackVersion     string        `json:"packVersion"`
	PackDigest      string        `json:"packDigest"`
	CreatedAt       string        `json:"createdAt"`
	Verdict         Verdict       `json:"verdict"`
	Summary         string        `json:"summary"`
	Drift           bool          `json:"drift"`
	Evidence        []EvidenceRef `json:"evidence"`
	Findings        []Finding     `json:"findings"`
	Sources         []PackSource  `json:"sources"`
}

type RemediationChange struct {
	Path         string `json:"path"`
	OldVersion   string `json:"oldVersion"`
	NewVersion   string `json:"newVersion"`
	Package      string `json:"package,omitempty"`
	Collector    string `json:"collector,omitempty"`
	Line         int    `json:"line,omitempty"`
	BeforeSHA256 string `json:"beforeSha256,omitempty"`
	Patch        string `json:"patch,omitempty"`
}

type RemediationProposal struct {
	APIVersion         string              `json:"apiVersion"`
	Kind               string              `json:"kind"`
	TrailID            string              `json:"trailId"`
	PackID             string              `json:"packId"`
	CreatedAt          string              `json:"createdAt"`
	Summary            string              `json:"summary"`
	Changes            []RemediationChange `json:"changes"`
	Steps              []string            `json:"steps"`
	Tests              []string            `json:"tests"`
	OperationalChecks  []string            `json:"operationalChecks"`
	RequiredApprovals  []string            `json:"requiredApprovals"`
	CredentialRotation []string            `json:"credentialRotation,omitempty"`
	Warnings           []string            `json:"warnings"`
}

type InTotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type InTotoStatement struct {
	Type          string           `json:"_type"`
	Subject       []InTotoSubject  `json:"subject"`
	PredicateType string           `json:"predicateType"`
	Predicate     ReceiptPredicate `json:"predicate"`
}

type ReceiptPredicate struct {
	ReceiptID       string            `json:"receiptId"`
	IssuedAt        string            `json:"issuedAt"`
	TrailID         string            `json:"trailId"`
	PreviousTrailID string            `json:"previousTrailId,omitempty"`
	PackID          string            `json:"packId"`
	PackVersion     string            `json:"packVersion"`
	PackDigest      string            `json:"packDigest"`
	Verdict         Verdict           `json:"verdict"`
	OpenVEX         OpenVEXDocument   `json:"openVex"`
	Evidence        []ReceiptEvidence `json:"evidence"`
	Limitations     []string          `json:"limitations"`
}

type ReceiptEvidence struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Digest     string `json:"digest,omitempty"`
	AssetToken string `json:"assetToken"`
	Runtime    bool   `json:"runtime"`
}

type OpenVEXDocument struct {
	Context    string             `json:"@context"`
	ID         string             `json:"@id"`
	Author     string             `json:"author"`
	Role       string             `json:"role"`
	Timestamp  string             `json:"timestamp"`
	Version    int                `json:"version"`
	Tooling    string             `json:"tooling"`
	Statements []OpenVEXStatement `json:"statements"`
}

type OpenVEXStatement struct {
	Vulnerability OpenVEXVulnerability `json:"vulnerability"`
	Products      []OpenVEXProduct     `json:"products"`
	Status        string               `json:"status"`
	StatusNotes   string               `json:"status_notes"`
}

type OpenVEXVulnerability struct {
	Name string `json:"name"`
}

type OpenVEXProduct struct {
	ID     string            `json:"@id"`
	Hashes map[string]string `json:"hashes,omitempty"`
}

type DSSESignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type DSSEEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []DSSESignature `json:"signatures"`
}

type VerificationMaterial struct {
	Type      string `json:"type"`
	KeyID     string `json:"keyId"`
	PublicKey string `json:"publicKey"`
	Identity  string `json:"identity"`
	Trust     string `json:"trust"`
}

type ReceiptBundle struct {
	MediaType            string               `json:"mediaType"`
	DSSEEnvelope         DSSEEnvelope         `json:"dsseEnvelope"`
	VerificationMaterial VerificationMaterial `json:"verificationMaterial"`
}

type ReceiptVerification struct {
	IntegrityValid  bool    `json:"integrityValid"`
	IdentityTrusted bool    `json:"identityTrusted"`
	Identity        string  `json:"identity"`
	ReceiptID       string  `json:"receiptId"`
	TrailID         string  `json:"trailId"`
	Verdict         Verdict `json:"verdict"`
	Message         string  `json:"message"`
}
