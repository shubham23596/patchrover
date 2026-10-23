package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/shubham23596/patchrover/internal/model"
)

func Assess(responsePack model.ResponsePack, evidence []model.EvidenceRef) (model.Trail, error) {
	return assessAt(responsePack, evidence, time.Now().UTC().Format(time.RFC3339), "")
}

func assessAt(responsePack model.ResponsePack, evidence []model.EvidenceRef, createdAt, previousTrailID string) (model.Trail, error) {
	packDigest, err := responsePack.Digest()
	if err != nil {
		return model.Trail{}, err
	}
	findings := make([]model.Finding, 0)
	for _, item := range evidence {
		for _, matcher := range responsePack.Spec.Matchers {
			if !matcherApplies(matcher, item) {
				continue
			}
			status, reason := evaluateMatcher(matcher, item)
			findings = append(findings, model.Finding{
				MatcherID:  matcher.ID,
				EvidenceID: item.ID,
				Status:     status,
				Reason:     reason,
				Runtime:    item.Runtime,
			})
		}
	}
	contradictory := hasContradiction(findings, evidence)
	verdict := aggregate(findings)
	if contradictory {
		verdict = model.VerdictUnknown
	}
	drift := !contradictory && hasDrift(findings)
	summary := summarize(verdict, drift, contradictory, findings)
	trailID, err := makeTrailID(responsePack.Metadata.ID, packDigest, createdAt, previousTrailID, evidence)
	if err != nil {
		return model.Trail{}, err
	}
	return model.Trail{
		APIVersion:      model.APIVersion,
		Kind:            "Trail",
		ID:              trailID,
		PreviousTrailID: previousTrailID,
		PackID:          responsePack.Metadata.ID,
		PackVersion:     responsePack.Metadata.Version,
		PackDigest:      packDigest,
		CreatedAt:       createdAt,
		Verdict:         verdict,
		Summary:         summary,
		Drift:           drift,
		Evidence:        evidence,
		Findings:        findings,
		Sources:         responsePack.Spec.Sources,
	}, nil
}

func LinkPrevious(responsePack model.ResponsePack, trail model.Trail, previousTrailID string) (model.Trail, error) {
	if err := ValidateTrail(responsePack, trail); err != nil {
		return model.Trail{}, err
	}
	if strings.TrimSpace(previousTrailID) == "" {
		return model.Trail{}, errors.New("previous trail ID is required")
	}
	return assessAt(responsePack, trail.Evidence, trail.CreatedAt, previousTrailID)
}

func ValidateTrail(responsePack model.ResponsePack, trail model.Trail) error {
	if trail.APIVersion != model.APIVersion || trail.Kind != "Trail" {
		return errors.New("invalid PatchRover trail type")
	}
	if _, err := time.Parse(time.RFC3339, trail.CreatedAt); err != nil {
		return errors.New("invalid PatchRover trail timestamp")
	}
	expected, err := assessAt(responsePack, trail.Evidence, trail.CreatedAt, trail.PreviousTrailID)
	if err != nil {
		return err
	}
	if trail.ID != expected.ID || trail.PackID != expected.PackID || trail.PackVersion != expected.PackVersion || trail.PackDigest != expected.PackDigest {
		return errors.New("trail identity does not match its pack, timestamp, chain link, or evidence")
	}
	if trail.Verdict != expected.Verdict || trail.Drift != expected.Drift || trail.Summary != expected.Summary || !reflect.DeepEqual(trail.Findings, expected.Findings) || !reflect.DeepEqual(trail.Sources, expected.Sources) {
		return errors.New("trail verdict, findings, or sources were modified")
	}
	return nil
}

func SuggestedFixedVersion(matcher model.Matcher, current string) string {
	for _, minimum := range matcher.MinimumFixedVersions {
		if sameLine(current, minimum.Line) {
			return minimum.Version
		}
	}
	if len(matcher.FixedVersions) > 0 {
		return matcher.FixedVersions[0]
	}
	return ""
}

func matcherApplies(matcher model.Matcher, evidence model.EvidenceRef) bool {
	if normalize(matcher.Name) != normalize(evidence.Name) {
		return false
	}
	for _, kind := range matcher.ArtifactKinds {
		if kind == evidence.Kind || kind == "*" {
			return true
		}
	}
	return false
}

func evaluateMatcher(matcher model.Matcher, evidence model.EvidenceRef) (model.Verdict, string) {
	if evidence.Digest != "" {
		for _, digest := range matcher.AffectedDigests {
			if strings.EqualFold(evidence.Digest, digest) {
				return model.VerdictAffected, "digest matches a published affected artifact"
			}
		}
	}
	if evidence.Version == "" {
		return model.VerdictUnknown, "matching artifact lacks a version and no affected digest matched"
	}
	for _, version := range matcher.AffectedVersions {
		if evidence.Version == version {
			return model.VerdictAffected, "version is explicitly listed as affected"
		}
	}
	for _, affectedRange := range matcher.AffectedVersionRanges {
		if sameLine(evidence.Version, affectedRange.Line) {
			comparison, ok := compareVersion(evidence.Version, affectedRange.LessThan)
			if !ok {
				return model.VerdictUnknown, "version could not be safely compared with the affected range"
			}
			if comparison < 0 {
				return model.VerdictAffected, "version is below the minimum fixed version for its supported line"
			}
		}
	}
	for _, version := range matcher.FixedVersions {
		if evidence.Version == version {
			return model.VerdictFixed, "version is explicitly listed as fixed"
		}
	}
	for _, minimum := range matcher.MinimumFixedVersions {
		if sameLine(evidence.Version, minimum.Line) {
			comparison, ok := compareVersion(evidence.Version, minimum.Version)
			if !ok {
				return model.VerdictUnknown, "version could not be safely compared with the fixed minimum"
			}
			if comparison >= 0 {
				return model.VerdictFixed, "version meets the minimum fixed version for its supported line"
			}
		}
	}
	return model.VerdictUnknown, "artifact is relevant but the pack has no decisive rule for this version or digest"
}

func aggregate(findings []model.Finding) model.Verdict {
	if len(findings) == 0 {
		return model.VerdictUnknown
	}
	hasFixed := false
	hasUnknown := false
	for _, finding := range findings {
		switch finding.Status {
		case model.VerdictAffected:
			return model.VerdictAffected
		case model.VerdictFixed:
			hasFixed = true
		default:
			hasUnknown = true
		}
	}
	if hasFixed && !hasUnknown {
		return model.VerdictFixed
	}
	return model.VerdictUnknown
}

func hasDrift(findings []model.Finding) bool {
	sourceFixed := false
	runtimeAffected := false
	for _, finding := range findings {
		if finding.Runtime && finding.Status == model.VerdictAffected {
			runtimeAffected = true
		}
		if !finding.Runtime && finding.Status == model.VerdictFixed {
			sourceFixed = true
		}
	}
	return sourceFixed && runtimeAffected
}

func hasContradiction(findings []model.Finding, evidence []model.EvidenceRef) bool {
	evidenceByID := make(map[string]model.EvidenceRef, len(evidence))
	for _, item := range evidence {
		evidenceByID[item.ID] = item
	}
	type observedStatus struct {
		affected bool
		fixed    bool
	}
	statuses := map[string]observedStatus{}
	for _, finding := range findings {
		item, ok := evidenceByID[finding.EvidenceID]
		if !ok || strings.TrimSpace(item.AssetID) == "" {
			continue
		}
		key := finding.MatcherID + "\x00" + item.Source + "\x00" + item.AssetID
		status := statuses[key]
		switch finding.Status {
		case model.VerdictAffected:
			status.affected = true
		case model.VerdictFixed:
			status.fixed = true
		}
		if status.affected && status.fixed {
			return true
		}
		statuses[key] = status
	}
	return false
}

func summarize(verdict model.Verdict, drift, contradictory bool, findings []model.Finding) string {
	if contradictory {
		return "Conflicting affected and fixed observations were supplied for the same asset. Resolve the evidence conflict before drawing a safety conclusion."
	}
	if drift {
		return "A fixed source artifact was observed, but affected runtime evidence is still present. The fix has not reached every observed workload."
	}
	switch verdict {
	case model.VerdictAffected:
		return "At least one observed artifact matches an affected version or digest. Review the cited evidence and remediation plan."
	case model.VerdictFixed:
		return "Every relevant observed artifact matched an explicit fixed rule. This does not prove the wider environment is secure."
	case model.VerdictNotAffected:
		return "Explicit absence evidence satisfied the response pack. PatchRover does not infer absence automatically."
	default:
		if len(findings) == 0 {
			return "No decisive artifact evidence was found. PatchRover will not infer safety from missing data."
		}
		return "Relevant evidence was found, but at least one item could not be classified safely."
	}
}

func makeTrailID(packID, packDigest, createdAt, previousTrailID string, evidence []model.EvidenceRef) (string, error) {
	data, err := json.Marshal(struct {
		PackID          string              `json:"packId"`
		PackDigest      string              `json:"packDigest"`
		CreatedAt       string              `json:"createdAt"`
		PreviousTrailID string              `json:"previousTrailId,omitempty"`
		Evidence        []model.EvidenceRef `json:"evidence"`
	}{packID, packDigest, createdAt, previousTrailID, evidence})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "trail-" + hex.EncodeToString(sum[:10]), nil
}

func sameLine(version, line string) bool {
	versionParts, ok := numericVersion(version)
	if !ok {
		return false
	}
	lineParts, ok := numericVersion(line)
	if !ok || len(lineParts) > len(versionParts) {
		return false
	}
	for index := range lineParts {
		if versionParts[index] != lineParts[index] {
			return false
		}
	}
	return true
}

func compareVersion(left, right string) (int, bool) {
	leftParts, ok := numericVersion(left)
	if !ok {
		return 0, false
	}
	rightParts, ok := numericVersion(right)
	if !ok {
		return 0, false
	}
	length := len(leftParts)
	if len(rightParts) > length {
		length = len(rightParts)
	}
	for index := 0; index < length; index++ {
		leftValue := 0
		rightValue := 0
		if index < len(leftParts) {
			leftValue = leftParts[index]
		}
		if index < len(rightParts) {
			rightValue = rightParts[index]
		}
		if leftValue < rightValue {
			return -1, true
		}
		if leftValue > rightValue {
			return 1, true
		}
	}
	return 0, true
}

func numericVersion(version string) ([]int, bool) {
	version = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(version), "v"))
	if version == "" {
		return nil, false
	}
	if index := strings.IndexAny(version, "+-"); index >= 0 {
		version = version[:index]
	}
	parts := strings.Split(version, ".")
	result := make([]int, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, false
		}
		value, err := strconv.Atoi(part)
		if err != nil {
			return nil, false
		}
		result = append(result, value)
	}
	return result, true
}

func normalize(value string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "_", "-"))
}

func FindingForEvidence(trail model.Trail, evidenceID string) (model.Finding, bool) {
	for _, finding := range trail.Findings {
		if finding.EvidenceID == evidenceID {
			return finding, true
		}
	}
	return model.Finding{}, false
}

func MatcherByID(responsePack model.ResponsePack, matcherID string) (model.Matcher, bool) {
	for _, matcher := range responsePack.Spec.Matchers {
		if matcher.ID == matcherID {
			return matcher, true
		}
	}
	return model.Matcher{}, false
}

func ExplainFinding(finding model.Finding) string {
	return fmt.Sprintf("%s: %s", finding.Status, finding.Reason)
}
