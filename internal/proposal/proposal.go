package proposal

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/shubham23596/patchrover/internal/engine"
	"github.com/shubham23596/patchrover/internal/model"
)

func Build(responsePack model.ResponsePack, trail model.Trail, repositoryRoot string) model.RemediationProposal {
	proposal := model.RemediationProposal{
		APIVersion:         model.APIVersion,
		Kind:               "RemediationProposal",
		TrailID:            trail.ID,
		PackID:             trail.PackID,
		CreatedAt:          time.Now().UTC().Format(time.RFC3339),
		Summary:            responsePack.Spec.Remediation.Summary,
		Steps:              append([]string(nil), responsePack.Spec.Remediation.Steps...),
		Tests:              append([]string(nil), responsePack.Spec.Remediation.Tests...),
		OperationalChecks:  append([]string(nil), responsePack.Spec.Remediation.OperationalChecks...),
		RequiredApprovals:  append([]string(nil), responsePack.Spec.Remediation.RequiredApprovals...),
		CredentialRotation: append([]string(nil), responsePack.Spec.Remediation.CredentialRotation...),
		Warnings: []string{
			"PatchRover did not modify the repository, push a branch, open a pull request, or deploy a workload.",
			"Review every proposed change and operational step with the responsible engineering and security owners.",
		},
	}
	if responsePack.Spec.Remediation.CompromiseAssumption != "" {
		proposal.Warnings = append(proposal.Warnings, responsePack.Spec.Remediation.CompromiseAssumption)
	}
	if trail.Verdict != model.VerdictAffected {
		proposal.Warnings = append(proposal.Warnings, "The trail is not currently affected; no automatic source change is proposed.")
		return proposal
	}
	for _, evidence := range trail.Evidence {
		finding, ok := engine.FindingForEvidence(trail, evidence.ID)
		if !ok || finding.Status != model.VerdictAffected || evidence.Runtime || evidence.Location == "" {
			continue
		}
		matcher, ok := engine.MatcherByID(responsePack, finding.MatcherID)
		if !ok {
			continue
		}
		fixedVersion := engine.SuggestedFixedVersion(matcher, evidence.Version)
		if fixedVersion == "" || evidence.Version == "" {
			continue
		}
		path, line := splitLocation(evidence.Location)
		if path == "" || repositoryRoot == "" {
			continue
		}
		absolutePath, safe := safeRepositoryPath(repositoryRoot, path)
		if !safe {
			proposal.Warnings = append(proposal.Warnings, fmt.Sprintf("Skipped unsafe evidence path %q.", path))
			continue
		}
		content, err := os.ReadFile(absolutePath)
		if err != nil {
			proposal.Warnings = append(proposal.Warnings, fmt.Sprintf("Could not read %s to prepare a patch: %v", path, err))
			continue
		}
		updated, changed := replaceVersion(string(content), evidence, fixedVersion, line)
		if !changed {
			proposal.Warnings = append(proposal.Warnings, fmt.Sprintf("No exact safe replacement was found in %s.", path))
			continue
		}
		proposal.Changes = append(proposal.Changes, model.RemediationChange{
			Path:         path,
			OldVersion:   evidence.Version,
			NewVersion:   fixedVersion,
			Package:      evidence.Name,
			Collector:    evidence.Collector,
			Line:         line,
			BeforeSHA256: contentSHA256(content),
			Patch:        unifiedDiff(path, string(content), updated, line),
		})
	}
	if len(proposal.Changes) == 0 {
		proposal.Warnings = append(proposal.Warnings, "No mechanically safe local diff was available; follow the structured remediation steps manually.")
	}
	return proposal
}

// ApplyChange applies one mechanically generated dependency change only when
// the current file still matches the content assessed by PatchRover.
func ApplyChange(content []byte, change model.RemediationChange) ([]byte, error) {
	if change.Path == "" || change.OldVersion == "" || change.NewVersion == "" || change.Package == "" || change.Collector == "" || change.Line < 1 || change.BeforeSHA256 == "" {
		return nil, fmt.Errorf("remediation change is missing bounded-apply metadata")
	}
	if contentSHA256(content) != change.BeforeSHA256 {
		return nil, fmt.Errorf("%s changed after assessment; refusing automatic edit", change.Path)
	}
	updated, changed := replaceVersion(string(content), model.EvidenceRef{
		Name:      change.Package,
		Version:   change.OldVersion,
		Collector: change.Collector,
	}, change.NewVersion, change.Line)
	if !changed {
		return nil, fmt.Errorf("no exact safe replacement remains in %s", change.Path)
	}
	return []byte(updated), nil
}

func contentSHA256(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func Markdown(proposal model.RemediationProposal, sources []model.PackSource) string {
	var builder strings.Builder
	builder.WriteString("# PatchRover remediation proposal\n\n")
	builder.WriteString("**Trail:** `" + proposal.TrailID + "`  \n")
	builder.WriteString("**Response pack:** `" + proposal.PackID + "`  \n")
	builder.WriteString("**Generated:** " + proposal.CreatedAt + "\n\n")
	builder.WriteString("> This is a local proposal. PatchRover did not push, deploy, or modify production.\n\n")
	builder.WriteString("## Summary\n\n" + proposal.Summary + "\n\n")
	if len(proposal.Changes) > 0 {
		builder.WriteString("## Proposed source changes\n\n")
		for _, change := range proposal.Changes {
			builder.WriteString(fmt.Sprintf("### `%s`\n\n%s → %s\n\n```diff\n%s\n```\n\n", change.Path, change.OldVersion, change.NewVersion, change.Patch))
		}
	}
	writeList(&builder, "Response steps", proposal.Steps)
	writeList(&builder, "Tests", proposal.Tests)
	writeList(&builder, "Operational checks", proposal.OperationalChecks)
	writeList(&builder, "Required approvals", proposal.RequiredApprovals)
	writeList(&builder, "Credential rotation", proposal.CredentialRotation)
	writeList(&builder, "Warnings", proposal.Warnings)
	if len(sources) > 0 {
		builder.WriteString("## Authoritative sources\n\n")
		for _, source := range sources {
			builder.WriteString(fmt.Sprintf("- [%s](%s)\n", source.Title, source.URL))
		}
		builder.WriteString("\n")
	}
	return builder.String()
}

func writeList(builder *strings.Builder, heading string, items []string) {
	if len(items) == 0 {
		return
	}
	builder.WriteString("## " + heading + "\n\n")
	for _, item := range items {
		builder.WriteString("- " + item + "\n")
	}
	builder.WriteString("\n")
}

func splitLocation(location string) (string, int) {
	index := strings.LastIndex(location, ":")
	if index < 0 {
		return location, 1
	}
	line, err := strconv.Atoi(location[index+1:])
	if err != nil {
		return location, 1
	}
	return location[:index], line
}

func safeRepositoryPath(root, relative string) (string, bool) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", false
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", false
	}
	candidate, err := filepath.Abs(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		return "", false
	}
	info, err := os.Lstat(candidate)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", false
	}
	resolvedCandidate, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", false
	}
	relativeToRoot, err := filepath.Rel(resolvedRoot, resolvedCandidate)
	if err != nil || filepath.IsAbs(relativeToRoot) || relativeToRoot == ".." || strings.HasPrefix(relativeToRoot, ".."+string(os.PathSeparator)) {
		return "", false
	}
	return resolvedCandidate, true
}

func replaceVersion(content string, evidence model.EvidenceRef, fixedVersion string, lineNumber int) (string, bool) {
	if lineNumber < 1 {
		return content, false
	}
	lines := strings.SplitAfter(content, "\n")
	if lineNumber > len(lines) {
		return content, false
	}
	line := lines[lineNumber-1]
	old := evidence.Version
	candidates := []string{}
	switch evidence.Collector {
	case "requirements", "python-lock":
		candidates = append(candidates,
			evidence.Name+"=="+old,
			evidence.Name+" == "+old,
			"version = \""+old+"\"",
			"version = '"+old+"'",
		)
	case "dockerfile":
		fixedReferenceVersion := preserveImageTagSuffix(old, fixedVersion)
		candidates = append(candidates, ":"+old, "@"+old)
		for _, candidate := range candidates {
			if strings.Contains(line, candidate) {
				replacement := strings.Replace(candidate, old, fixedReferenceVersion, 1)
				lines[lineNumber-1] = strings.Replace(line, candidate, replacement, 1)
				return strings.Join(lines, ""), true
			}
		}
		return content, false
	default:
		return content, false
	}
	for _, candidate := range candidates {
		if strings.Contains(line, candidate) {
			replacement := strings.Replace(candidate, old, fixedVersion, 1)
			lines[lineNumber-1] = strings.Replace(line, candidate, replacement, 1)
			return strings.Join(lines, ""), true
		}
	}
	return content, false
}

func preserveImageTagSuffix(oldVersion, fixedVersion string) string {
	index := len(oldVersion)
	for index > 0 {
		character := oldVersion[index-1]
		if character >= '0' && character <= '9' || character == '.' {
			break
		}
		index--
	}
	if index == len(oldVersion) || index == 0 {
		return fixedVersion
	}
	return fixedVersion + oldVersion[index:]
}

func unifiedDiff(path, before, after string, suggestedLine int) string {
	beforeLines := strings.Split(strings.TrimSuffix(before, "\n"), "\n")
	afterLines := strings.Split(strings.TrimSuffix(after, "\n"), "\n")
	first := 0
	limit := len(beforeLines)
	if len(afterLines) < limit {
		limit = len(afterLines)
	}
	for first < limit && beforeLines[first] == afterLines[first] {
		first++
	}
	if first == limit && len(beforeLines) == len(afterLines) {
		return ""
	}
	start := first - 2
	if start < 0 {
		start = 0
	}
	endBefore := first + 3
	if endBefore > len(beforeLines) {
		endBefore = len(beforeLines)
	}
	endAfter := first + 3
	if endAfter > len(afterLines) {
		endAfter = len(afterLines)
	}
	if suggestedLine > 0 && suggestedLine-1 < start {
		start = suggestedLine - 1
	}
	var builder strings.Builder
	builder.WriteString("--- a/" + path + "\n")
	builder.WriteString("+++ b/" + path + "\n")
	builder.WriteString(fmt.Sprintf("@@ -%d,%d +%d,%d @@\n", start+1, endBefore-start, start+1, endAfter-start))
	max := endBefore
	if endAfter > max {
		max = endAfter
	}
	for index := start; index < max; index++ {
		beforeLine := ""
		afterLine := ""
		if index < len(beforeLines) {
			beforeLine = beforeLines[index]
		}
		if index < len(afterLines) {
			afterLine = afterLines[index]
		}
		if beforeLine == afterLine {
			builder.WriteString(" " + beforeLine + "\n")
			continue
		}
		if index < len(beforeLines) {
			builder.WriteString("-" + beforeLine + "\n")
		}
		if index < len(afterLines) {
			builder.WriteString("+" + afterLine + "\n")
		}
	}
	return strings.TrimSuffix(builder.String(), "\n")
}
