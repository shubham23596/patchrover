package collect

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/shubham23596/patchrover/internal/model"
)

const maxEvidenceFileSize = 8 << 20

var (
	requirementPattern = regexp.MustCompile(`(?i)^\s*([a-z0-9_.-]+)(?:\[[^]]+\])?\s*==\s*([^\s;#]+)`)
	fromPattern        = regexp.MustCompile(`(?i)^\s*FROM\s+(?:--platform=[^\s]+\s+)?([^\s]+)`)
)

type Options struct {
	RepositoryPath       string   `json:"repositoryPath,omitempty"`
	SBOMPath             string   `json:"sbomPath,omitempty"`
	ImageReference       string   `json:"imageReference,omitempty"`
	ResolveImage         bool     `json:"resolveImage,omitempty"`
	ImagePlatform        string   `json:"imagePlatform,omitempty"`
	RegistryAllowedHosts []string `json:"registryAllowedHosts,omitempty"`
	RegistryTokenEnv     string   `json:"registryTokenEnv,omitempty"`
	EvidencePath         string   `json:"evidencePath,omitempty"`
	KubeContext          string   `json:"kubeContext,omitempty"`
	KubeSnapshot         string   `json:"kubeSnapshot,omitempty"`
}

func All(options Options) ([]model.EvidenceRef, error) {
	return AllContext(context.Background(), options)
}

func AllContext(ctx context.Context, options Options) ([]model.EvidenceRef, error) {
	if options.ResolveImage && options.ImageReference == "" {
		return nil, errors.New("live image resolution requires an explicit image reference")
	}
	if !options.ResolveImage && (len(options.RegistryAllowedHosts) > 0 || options.RegistryTokenEnv != "") {
		return nil, errors.New("registry settings require live image resolution")
	}
	if !options.ResolveImage && options.ImagePlatform != "" {
		return nil, errors.New("image platform selection requires live image resolution")
	}
	var evidence []model.EvidenceRef
	if options.RepositoryPath != "" {
		items, err := Repository(options.RepositoryPath)
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, items...)
	}
	if options.SBOMPath != "" {
		items, err := SBOM(options.SBOMPath)
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, items...)
	}
	if options.ImageReference != "" {
		var item model.EvidenceRef
		var err error
		if options.ResolveImage {
			item, err = ResolveImageReference(ctx, options.ImageReference, "cli-image", false, RegistryOptions{AllowedHosts: options.RegistryAllowedHosts, TokenEnv: options.RegistryTokenEnv, Platform: options.ImagePlatform})
		} else {
			item, err = ImageReference(options.ImageReference, "cli-image", false)
		}
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, item)
	}
	if options.EvidencePath != "" {
		items, err := EvidenceFile(options.EvidencePath)
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, items...)
	}
	if options.KubeSnapshot != "" {
		items, err := KubernetesSnapshotFile(options.KubeSnapshot)
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, items...)
	}
	if options.KubeContext != "" {
		items, err := Kubernetes(options.KubeContext)
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, items...)
	}
	return deduplicate(evidence), nil
}

func Repository(root string) ([]model.EvidenceRef, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("inspect repository path: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("repository path must be a directory")
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	var evidence []model.EvidenceRef
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && shouldSkipDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			if path != root && strings.Count(strings.TrimPrefix(path, root), string(os.PathSeparator)) > 8 {
				return filepath.SkipDir
			}
			return nil
		}
		name := strings.ToLower(entry.Name())
		switch {
		case name == "requirements.txt" || strings.HasSuffix(name, "-requirements.txt"):
			items, err := parseRequirements(path, root)
			if err != nil {
				return err
			}
			evidence = append(evidence, items...)
		case name == "poetry.lock" || name == "uv.lock":
			items, err := parsePythonLock(path, root)
			if err != nil {
				return err
			}
			evidence = append(evidence, items...)
		case name == "dockerfile" || strings.HasPrefix(name, "dockerfile."):
			items, err := parseDockerfile(path, root)
			if err != nil {
				return err
			}
			evidence = append(evidence, items...)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("collect repository evidence: %w", err)
	}
	return evidence, nil
}

func parseRequirements(path, root string) ([]model.EvidenceRef, error) {
	file, err := openSmallFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var evidence []model.EvidenceRef
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		match := requirementPattern.FindStringSubmatch(scanner.Text())
		if len(match) != 3 {
			continue
		}
		location := relativeLocation(root, path, lineNumber)
		evidence = append(evidence, makeEvidence("repository", location, "requirements", "python-package", normalizePackage(match[1]), match[2], "", location, false, "high", "exactly pinned Python dependency"))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return evidence, nil
}

func parsePythonLock(path, root string) ([]model.EvidenceRef, error) {
	file, err := openSmallFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var evidence []model.EvidenceRef
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	packageName := ""
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "[[package]]" {
			packageName = ""
			continue
		}
		if strings.HasPrefix(line, "name = ") {
			packageName = trimTOMLString(strings.TrimSpace(strings.TrimPrefix(line, "name = ")))
			continue
		}
		if packageName != "" && strings.HasPrefix(line, "version = ") {
			version := trimTOMLString(strings.TrimSpace(strings.TrimPrefix(line, "version = ")))
			if version != "" {
				location := relativeLocation(root, path, lineNumber)
				evidence = append(evidence, makeEvidence("repository", location, "python-lock", "python-package", normalizePackage(packageName), version, "", location, false, "high", "locked Python dependency"))
			}
			packageName = ""
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return evidence, nil
}

func parseDockerfile(path, root string) ([]model.EvidenceRef, error) {
	file, err := openSmallFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var evidence []model.EvidenceRef
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		match := fromPattern.FindStringSubmatch(scanner.Text())
		if len(match) != 2 {
			continue
		}
		location := relativeLocation(root, path, lineNumber)
		item, err := ImageReference(match[1], location, false)
		if err != nil {
			continue
		}
		item.Source = "repository"
		item.Collector = "dockerfile"
		item.Location = location
		item.AssetID = location
		item.ID = evidenceID(item)
		evidence = append(evidence, item)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return evidence, nil
}

func ImageReference(reference, assetID string, runtime bool) (model.EvidenceRef, error) {
	reference = strings.TrimSpace(reference)
	if reference == "" || strings.ContainsAny(reference, "\r\n\x00") {
		return model.EvidenceRef{}, errors.New("invalid OCI image reference")
	}
	if ociDigestPattern.MatchString(reference) {
		return makeEvidence("image", assetID, "oci-reference", "oci-image", "oci-image", "", strings.ToLower(reference), "", runtime, "high", "OCI image digest"), nil
	}
	withoutDigest := reference
	digest := ""
	if before, after, found := strings.Cut(reference, "@"); found {
		withoutDigest = before
		if strings.Contains(after, "@") || !ociDigestPattern.MatchString(after) {
			return model.EvidenceRef{}, errors.New("OCI image digest must be sha256 followed by 64 hexadecimal characters")
		}
		digest = strings.ToLower(after)
	}
	lastSlash := strings.LastIndex(withoutDigest, "/")
	lastColon := strings.LastIndex(withoutDigest, ":")
	version := ""
	namePart := withoutDigest
	if lastColon > lastSlash {
		version = withoutDigest[lastColon+1:]
		namePart = withoutDigest[:lastColon]
	}
	name := namePart
	if slash := strings.LastIndex(namePart, "/"); slash >= 0 {
		name = namePart[slash+1:]
	}
	name = normalizePackage(name)
	if strings.HasPrefix(name, "php-") || name == "php" {
		name = "php"
	}
	if strings.Contains(name, "litellm") {
		name = "litellm"
	}
	kind := "oci-image"
	if name == "php" {
		kind = "runtime"
	}
	detail := "OCI image reference"
	confidence := "medium"
	if digest != "" {
		detail = "OCI image reference pinned by digest"
		confidence = "high"
	}
	item := makeEvidence("image", assetID, "oci-reference", kind, name, version, digest, "", runtime, confidence, detail)
	return item, nil
}

func EvidenceFile(path string) ([]model.EvidenceRef, error) {
	data, err := readSmallFile(path)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Evidence []model.EvidenceRef `json:"evidence"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode evidence file: %w", err)
	}
	if len(envelope.Evidence) == 0 {
		return nil, errors.New("evidence file contains no evidence")
	}
	for index := range envelope.Evidence {
		item := &envelope.Evidence[index]
		item.Source = "explicit-evidence"
		item.Collector = "evidence-file"
		if item.ObservedAt == "" {
			item.ObservedAt = time.Now().UTC().Format(time.RFC3339)
		}
		if item.Confidence == "" {
			item.Confidence = "operator-provided"
		}
		if item.ID == "" {
			item.ID = evidenceID(*item)
		}
	}
	return envelope.Evidence, nil
}

func SBOM(path string) ([]model.EvidenceRef, error) {
	data, err := readSmallFile(path)
	if err != nil {
		return nil, err
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("decode SBOM: %w", err)
	}
	var evidence []model.EvidenceRef
	if components, ok := document["components"].([]any); ok {
		collectCycloneDXComponents(components, path, &evidence)
	}
	if packages, ok := document["packages"].([]any); ok {
		for _, raw := range packages {
			entry, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			name, _ := entry["name"].(string)
			version, _ := entry["versionInfo"].(string)
			if name == "" || version == "" {
				continue
			}
			digest := firstSPDXSHA256(entry["checksums"])
			evidence = append(evidence, makeEvidence("sbom", filepath.Base(path), "spdx-json", packageKind(name, ""), normalizePackage(name), version, digest, filepath.Base(path), false, "high", "SPDX package"))
		}
	}
	if len(evidence) == 0 {
		return nil, errors.New("SBOM contains no supported CycloneDX components or SPDX packages")
	}
	return evidence, nil
}

func Kubernetes(contextName string) ([]model.EvidenceRef, error) {
	if strings.TrimSpace(contextName) == "" || len(contextName) > 256 || strings.ContainsAny(contextName, "\r\n\x00") {
		return nil, errors.New("invalid Kubernetes context")
	}
	path, err := exec.LookPath("kubectl")
	if err != nil {
		return nil, errors.New("kubectl is required for --kube-context; use --kube-snapshot for offline evidence")
	}
	command := exec.Command(path, "--context", contextName, "get", "pods", "--all-namespaces", "-o", "json", "--request-timeout=15s")
	command.Env = append(os.Environ(), "KUBECTL_EXTERNAL_DIFF=")
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("read Kubernetes pod metadata: %w", err)
	}
	return KubernetesSnapshot(output, "kube-context:"+contextName)
}

func KubernetesSnapshotFile(path string) ([]model.EvidenceRef, error) {
	data, err := readSmallFile(path)
	if err != nil {
		return nil, err
	}
	return KubernetesSnapshot(data, "kube-snapshot:"+filepath.Base(path))
}

func KubernetesSnapshot(data []byte, source string) ([]model.EvidenceRef, error) {
	type containerSpec struct {
		Name  string `json:"name"`
		Image string `json:"image"`
	}
	type containerStatus struct {
		Name    string `json:"name"`
		Image   string `json:"image"`
		ImageID string `json:"imageID"`
	}
	type pod struct {
		Metadata struct {
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"metadata"`
		Spec struct {
			Containers []containerSpec `json:"containers"`
		} `json:"spec"`
		Status struct {
			ContainerStatuses []containerStatus `json:"containerStatuses"`
		} `json:"status"`
	}
	var list struct {
		Items []pod `json:"items"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("decode Kubernetes pod list: %w", err)
	}
	statusByPod := map[string]map[string]containerStatus{}
	for _, item := range list.Items {
		podID := item.Metadata.Namespace + "/" + item.Metadata.Name
		statusByPod[podID] = map[string]containerStatus{}
		for _, status := range item.Status.ContainerStatuses {
			statusByPod[podID][status.Name] = status
		}
	}
	var evidence []model.EvidenceRef
	for _, item := range list.Items {
		podID := item.Metadata.Namespace + "/" + item.Metadata.Name
		for _, container := range item.Spec.Containers {
			status := statusByPod[podID][container.Name]
			image := container.Image
			if status.Image != "" {
				image = status.Image
			}
			ref, err := ImageReference(image, podID+"/"+container.Name, true)
			if err != nil {
				continue
			}
			if digest := extractDigest(status.ImageID); digest != "" {
				ref.Digest = digest
				ref.Confidence = "high"
				ref.Detail = "running Kubernetes container image digest"
			} else {
				ref.Detail = "Kubernetes container image tag without runtime digest"
			}
			ref.Source = source
			ref.Collector = "kubernetes-pods"
			ref.Location = "redacted-kubernetes-workload"
			ref.ID = evidenceID(ref)
			evidence = append(evidence, ref)
		}
	}
	if len(evidence) == 0 {
		return nil, errors.New("Kubernetes snapshot contains no supported container evidence")
	}
	return evidence, nil
}

func collectCycloneDXComponents(components []any, source string, evidence *[]model.EvidenceRef) {
	for _, raw := range components {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name, _ := entry["name"].(string)
		version, _ := entry["version"].(string)
		purl, _ := entry["purl"].(string)
		if name != "" && version != "" {
			digest := firstCycloneDXSHA256(entry["hashes"])
			*evidence = append(*evidence, makeEvidence("sbom", filepath.Base(source), "cyclonedx-json", packageKind(name, purl), normalizePackage(name), version, digest, filepath.Base(source), false, "high", "CycloneDX component"))
		}
		if children, ok := entry["components"].([]any); ok {
			collectCycloneDXComponents(children, source, evidence)
		}
	}
}

func firstCycloneDXSHA256(raw any) string {
	hashes, ok := raw.([]any)
	if !ok {
		return ""
	}
	for _, value := range hashes {
		entry, ok := value.(map[string]any)
		if !ok {
			continue
		}
		algorithm, _ := entry["alg"].(string)
		content, _ := entry["content"].(string)
		if strings.EqualFold(algorithm, "SHA-256") && content != "" {
			return "sha256:" + strings.ToLower(content)
		}
	}
	return ""
}

func firstSPDXSHA256(raw any) string {
	checksums, ok := raw.([]any)
	if !ok {
		return ""
	}
	for _, value := range checksums {
		entry, ok := value.(map[string]any)
		if !ok {
			continue
		}
		algorithm, _ := entry["algorithm"].(string)
		checksum, _ := entry["checksumValue"].(string)
		if strings.EqualFold(algorithm, "SHA256") && checksum != "" {
			return "sha256:" + strings.ToLower(checksum)
		}
	}
	return ""
}

func packageKind(name, purl string) string {
	if strings.HasPrefix(strings.ToLower(purl), "pkg:pypi/") {
		return "python-package"
	}
	if strings.EqualFold(name, "php") {
		return "runtime"
	}
	return "package"
}

func makeEvidence(source, assetID, collector, kind, name, version, digest, location string, runtime bool, confidence, detail string) model.EvidenceRef {
	item := model.EvidenceRef{
		Source:     source,
		ObservedAt: time.Now().UTC().Format(time.RFC3339),
		AssetID:    assetID,
		Collector:  collector,
		Kind:       kind,
		Name:       normalizePackage(name),
		Version:    version,
		Digest:     strings.ToLower(digest),
		Location:   location,
		Runtime:    runtime,
		Confidence: confidence,
		Detail:     detail,
	}
	item.ID = evidenceID(item)
	return item
}

func evidenceID(item model.EvidenceRef) string {
	stable := strings.Join([]string{item.Source, item.AssetID, item.Collector, item.Kind, item.Name, item.Version, item.Digest, item.Location, fmt.Sprint(item.Runtime)}, "\x00")
	sum := sha256.Sum256([]byte(stable))
	return "ev-" + hex.EncodeToString(sum[:8])
}

func deduplicate(input []model.EvidenceRef) []model.EvidenceRef {
	byID := map[string]model.EvidenceRef{}
	for _, item := range input {
		if item.ID == "" {
			item.ID = evidenceID(item)
		}
		byID[item.ID] = item
	}
	keys := make([]string, 0, len(byID))
	for key := range byID {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]model.EvidenceRef, 0, len(keys))
	for _, key := range keys {
		result = append(result, byID[key])
	}
	return result
}

func shouldSkipDirectory(name string) bool {
	switch name {
	case ".git", ".hg", ".svn", "node_modules", "vendor", ".venv", "venv", "dist", "build", ".next", ".astro":
		return true
	default:
		return false
	}
}

func openSmallFile(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maxEvidenceFileSize {
		return nil, fmt.Errorf("refusing non-regular or oversized evidence file %q", path)
	}
	return os.Open(path)
}

func readSmallFile(path string) ([]byte, error) {
	file, err := openSmallFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

func relativeLocation(root, path string, line int) string {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		relative = filepath.Base(path)
	}
	return fmt.Sprintf("%s:%d", filepath.ToSlash(relative), line)
}

func trimTOMLString(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
		return value[1 : len(value)-1]
	}
	return ""
}

func normalizePackage(name string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), "_", "-"))
}

func extractDigest(imageID string) string {
	imageID = strings.TrimSpace(imageID)
	if index := strings.LastIndex(imageID, "sha256:"); index >= 0 {
		digest := imageID[index:]
		if len(digest) == len("sha256:")+64 {
			return strings.ToLower(digest)
		}
	}
	return ""
}
