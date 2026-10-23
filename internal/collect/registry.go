package collect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/shubham23596/patchrover/internal/model"
)

const (
	maxRegistryManifestBytes = 8 << 20
	maxRegistryTokenBytes    = 64 << 10
	maxRegistryIndexEntries  = 256
	maxRegistryIndexDepth    = 4
)

var (
	ociDigestPattern            = regexp.MustCompile(`^sha256:[a-fA-F0-9]{64}$`)
	ociTagPattern               = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	ociRepositoryPattern        = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*)*$`)
	ociPlatformPartPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,31}$`)
	bearerParameter             = regexp.MustCompile(`(?i)([a-z][a-z0-9_-]*)="([^"]*)"`)
	registryEnvPattern          = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	supportedManifestMediaTypes = map[string]bool{
		"application/vnd.oci.image.manifest.v1+json":                true,
		"application/vnd.oci.image.index.v1+json":                   true,
		"application/vnd.docker.distribution.manifest.v2+json":      true,
		"application/vnd.docker.distribution.manifest.list.v2+json": true,
	}
)

type RegistryOptions struct {
	AllowedHosts []string
	TokenEnv     string
	Platform     string
	HTTP         *http.Client
}

type imagePlatform struct {
	OS           string
	Architecture string
	Variant      string
}

func (platform imagePlatform) String() string {
	value := platform.OS + "/" + platform.Architecture
	if platform.Variant != "" {
		value += "/" + platform.Variant
	}
	return value
}

type registryResolution struct {
	Digest      string
	Platform    string
	IndexDigest string
}

type registryReference struct {
	Registry   string
	Repository string
	Reference  string
	Digest     string
}

func ResolveImageReference(ctx context.Context, reference, assetID string, runtime bool, options RegistryOptions) (model.EvidenceRef, error) {
	parsed, err := parseRegistryReference(reference)
	if err != nil {
		return model.EvidenceRef{}, err
	}
	requestedPlatform, err := parseImagePlatform(options.Platform)
	if err != nil {
		return model.EvidenceRef{}, err
	}
	item, err := ImageReference(reference, assetID, runtime)
	if err != nil {
		return model.EvidenceRef{}, err
	}
	if parsed.Digest != "" {
		if requestedPlatform != nil {
			return model.EvidenceRef{}, errors.New("image platform selection requires a tagged reference that resolves to an image index")
		}
		return item, nil
	}
	allowed, err := registryAllowedHosts(options.AllowedHosts)
	if err != nil {
		return model.EvidenceRef{}, err
	}
	if !allowed[parsed.Registry] {
		return model.EvidenceRef{}, fmt.Errorf("registry host %q is not explicitly allowlisted", parsed.Registry)
	}
	client := restrictedRegistryHTTPClient(options.HTTP, allowed)
	token := ""
	if options.TokenEnv != "" {
		if !registryEnvPattern.MatchString(options.TokenEnv) {
			return model.EvidenceRef{}, errors.New("invalid registry token environment variable name")
		}
		token = os.Getenv(options.TokenEnv)
		if token == "" {
			return model.EvidenceRef{}, fmt.Errorf("registry token environment variable %s is empty", options.TokenEnv)
		}
		if len(token) > 16<<10 || strings.ContainsAny(token, "\r\n\x00") {
			return model.EvidenceRef{}, errors.New("registry bearer token is invalid")
		}
	}
	resolution, err := resolveRegistryManifest(ctx, client, parsed, allowed, token, requestedPlatform)
	if err != nil {
		return model.EvidenceRef{}, err
	}
	item.Digest = resolution.Digest
	item.Platform = resolution.Platform
	item.IndexDigest = resolution.IndexDigest
	item.Confidence = "high"
	item.Detail = "OCI registry manifest resolved and digest verified"
	if resolution.Platform != "" {
		item.Detail = fmt.Sprintf("OCI %s manifest selected from verified index %s", resolution.Platform, resolution.IndexDigest)
	}
	item.ID = evidenceID(item)
	return item, nil
}

func ValidateRegistryResolution(reference string, options RegistryOptions) error {
	parsed, err := parseRegistryReference(reference)
	if err != nil {
		return err
	}
	requestedPlatform, err := parseImagePlatform(options.Platform)
	if err != nil {
		return err
	}
	allowed, err := registryAllowedHosts(options.AllowedHosts)
	if err != nil {
		return err
	}
	if options.TokenEnv != "" && !registryEnvPattern.MatchString(options.TokenEnv) {
		return errors.New("invalid registry token environment variable name")
	}
	if parsed.Digest != "" {
		if requestedPlatform != nil {
			return errors.New("image platform selection requires a tagged reference that resolves to an image index")
		}
		return nil
	}
	if !allowed[parsed.Registry] {
		return fmt.Errorf("registry host %q is not explicitly allowlisted", parsed.Registry)
	}
	return nil
}

func parseImagePlatform(value string) (*imagePlatform, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, errors.New("OCI image platform must be OS/architecture or OS/architecture/variant")
	}
	for _, part := range parts {
		if !ociPlatformPartPattern.MatchString(part) {
			return nil, errors.New("OCI image platform contains an invalid component")
		}
	}
	if parts[0] != "linux" {
		return nil, errors.New("PatchRover currently supports Linux OCI image platforms only")
	}
	platform := &imagePlatform{OS: parts[0], Architecture: parts[1]}
	if len(parts) == 3 {
		platform.Variant = parts[2]
	}
	return platform, nil
}

func parseRegistryReference(reference string) (registryReference, error) {
	reference = strings.TrimSpace(reference)
	if reference == "" || len(reference) > 512 || strings.ContainsAny(reference, "\r\n\x00?#") || strings.Contains(reference, "://") {
		return registryReference{}, errors.New("invalid OCI image reference")
	}
	if ociDigestPattern.MatchString(reference) {
		return registryReference{Digest: strings.ToLower(reference)}, nil
	}
	namePart := reference
	parsed := registryReference{}
	if before, after, found := strings.Cut(reference, "@"); found {
		if strings.Contains(after, "@") || !ociDigestPattern.MatchString(after) {
			return registryReference{}, errors.New("OCI image digest must be sha256 followed by 64 hexadecimal characters")
		}
		namePart = before
		parsed.Digest = strings.ToLower(after)
		parsed.Reference = parsed.Digest
	}
	if namePart == "" {
		return registryReference{}, errors.New("OCI image reference is missing a repository")
	}
	if parsed.Reference == "" {
		lastSlash := strings.LastIndex(namePart, "/")
		lastColon := strings.LastIndex(namePart, ":")
		if lastColon > lastSlash {
			parsed.Reference = namePart[lastColon+1:]
			namePart = namePart[:lastColon]
		} else {
			parsed.Reference = "latest"
		}
		if !ociTagPattern.MatchString(parsed.Reference) {
			return registryReference{}, errors.New("invalid OCI image tag")
		}
	}
	parts := strings.Split(namePart, "/")
	if len(parts) == 0 {
		return registryReference{}, errors.New("invalid OCI image repository")
	}
	first := strings.ToLower(parts[0])
	if strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost" {
		if len(parts) < 2 {
			return registryReference{}, errors.New("OCI registry reference is missing a repository path")
		}
		parsed.Registry = first
		parsed.Repository = strings.Join(parts[1:], "/")
	} else {
		parsed.Registry = "registry-1.docker.io"
		parsed.Repository = strings.Join(parts, "/")
		if len(parts) == 1 {
			parsed.Repository = "library/" + parsed.Repository
		}
	}
	if parsed.Registry == "docker.io" || parsed.Registry == "index.docker.io" {
		parsed.Registry = "registry-1.docker.io"
	}
	parsed.Repository = strings.ToLower(parsed.Repository)
	if !ociRepositoryPattern.MatchString(parsed.Repository) {
		return registryReference{}, errors.New("invalid OCI image repository path")
	}
	registryURL, err := url.Parse("https://" + parsed.Registry)
	if err != nil || registryURL.Host != parsed.Registry || registryURL.Hostname() == "" || registryURL.User != nil {
		return registryReference{}, errors.New("invalid OCI registry host")
	}
	return parsed, nil
}

func registryAllowedHosts(input []string) (map[string]bool, error) {
	allowed := map[string]bool{}
	for _, raw := range input {
		host := strings.ToLower(strings.TrimSpace(raw))
		if host == "" || len(host) > 255 || strings.ContainsAny(host, "/@?#") {
			return nil, fmt.Errorf("invalid registry allowed host %q", raw)
		}
		parsed, err := url.Parse("https://" + host)
		if err != nil || parsed.Host != host || parsed.Hostname() == "" || parsed.User != nil {
			return nil, fmt.Errorf("invalid registry allowed host %q", raw)
		}
		allowed[host] = true
	}
	return allowed, nil
}

func restrictedRegistryHTTPClient(original *http.Client, allowed map[string]bool) *http.Client {
	client := http.Client{Timeout: 20 * time.Second}
	if original != nil {
		client = *original
		if client.Timeout == 0 {
			client.Timeout = 20 * time.Second
		}
	}
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 || request.URL.Scheme != "https" || !allowed[strings.ToLower(request.URL.Host)] {
			return errors.New("OCI registry redirect left the explicit HTTPS host allowlist")
		}
		if len(via) > 0 && !strings.EqualFold(request.URL.Host, via[0].URL.Host) {
			return errors.New("OCI registry redirect changed hosts")
		}
		return nil
	}
	return &client
}

func resolveRegistryManifest(ctx context.Context, client *http.Client, reference registryReference, allowed map[string]bool, directToken string, requestedPlatform *imagePlatform) (registryResolution, error) {
	body, digest, mediaType, err := fetchAuthorizedRegistryManifest(ctx, client, reference, reference.Reference, allowed, directToken)
	if err != nil {
		return registryResolution{}, err
	}
	if requestedPlatform == nil {
		return registryResolution{Digest: digest}, nil
	}
	if !isRegistryIndexMediaType(mediaType) {
		return registryResolution{}, errors.New("registry returned a single image manifest; the requested platform cannot be proven from an image index")
	}
	rootIndexDigest := digest
	visited := map[string]bool{digest: true}
	for depth := 0; depth < maxRegistryIndexDepth; depth++ {
		descriptor, actualPlatform, selectErr := selectPlatformDescriptor(body, *requestedPlatform)
		if selectErr != nil {
			return registryResolution{}, selectErr
		}
		childBody, childDigest, childMediaType, fetchErr := fetchAuthorizedRegistryManifest(ctx, client, reference, descriptor.Digest, allowed, directToken)
		if fetchErr != nil {
			return registryResolution{}, fetchErr
		}
		if childDigest != descriptor.Digest {
			return registryResolution{}, errors.New("selected OCI platform descriptor digest does not match the fetched manifest")
		}
		if int64(len(childBody)) != descriptor.Size {
			return registryResolution{}, errors.New("selected OCI platform descriptor size does not match the fetched manifest")
		}
		if !strings.EqualFold(descriptor.MediaType, childMediaType) {
			return registryResolution{}, errors.New("selected OCI platform descriptor mediaType does not match the fetched manifest")
		}
		if isRegistryImageManifestMediaType(childMediaType) {
			return registryResolution{Digest: childDigest, Platform: actualPlatform.String(), IndexDigest: rootIndexDigest}, nil
		}
		if !isRegistryIndexMediaType(childMediaType) {
			return registryResolution{}, errors.New("selected OCI platform descriptor is not an image manifest or nested index")
		}
		if visited[childDigest] {
			return registryResolution{}, errors.New("OCI image index contains a descriptor cycle")
		}
		visited[childDigest] = true
		body = childBody
	}
	return registryResolution{}, fmt.Errorf("OCI image index nesting exceeds %d levels", maxRegistryIndexDepth)
}

type registryIndexDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
		Variant      string `json:"variant,omitempty"`
	} `json:"platform,omitempty"`
}

func selectPlatformDescriptor(body []byte, requested imagePlatform) (registryIndexDescriptor, imagePlatform, error) {
	var index struct {
		SchemaVersion int                       `json:"schemaVersion"`
		Manifests     []registryIndexDescriptor `json:"manifests"`
	}
	if err := json.Unmarshal(body, &index); err != nil || index.SchemaVersion != 2 {
		return registryIndexDescriptor{}, imagePlatform{}, errors.New("decode OCI image index")
	}
	if len(index.Manifests) == 0 {
		return registryIndexDescriptor{}, imagePlatform{}, errors.New("OCI image index contains no manifest descriptors")
	}
	if len(index.Manifests) > maxRegistryIndexEntries {
		return registryIndexDescriptor{}, imagePlatform{}, fmt.Errorf("OCI image index exceeds %d manifest descriptors", maxRegistryIndexEntries)
	}
	type candidate struct {
		descriptor registryIndexDescriptor
		platform   imagePlatform
	}
	var candidates []candidate
	for _, descriptor := range index.Manifests {
		if descriptor.Platform == nil {
			continue
		}
		actual := imagePlatform{
			OS:           strings.ToLower(strings.TrimSpace(descriptor.Platform.OS)),
			Architecture: strings.ToLower(strings.TrimSpace(descriptor.Platform.Architecture)),
			Variant:      strings.ToLower(strings.TrimSpace(descriptor.Platform.Variant)),
		}
		if actual.OS != requested.OS || actual.Architecture != requested.Architecture {
			continue
		}
		if requested.Variant != "" && actual.Variant != requested.Variant {
			continue
		}
		if !ociPlatformPartPattern.MatchString(actual.OS) || !ociPlatformPartPattern.MatchString(actual.Architecture) || (actual.Variant != "" && !ociPlatformPartPattern.MatchString(actual.Variant)) {
			return registryIndexDescriptor{}, imagePlatform{}, errors.New("matching OCI image index descriptor has an invalid platform")
		}
		descriptor.Digest = strings.ToLower(strings.TrimSpace(descriptor.Digest))
		descriptor.MediaType = strings.ToLower(strings.TrimSpace(descriptor.MediaType))
		if !ociDigestPattern.MatchString(descriptor.Digest) || descriptor.Size < 1 {
			return registryIndexDescriptor{}, imagePlatform{}, errors.New("matching OCI image index descriptor has an invalid digest or size")
		}
		if !supportedManifestMediaTypes[descriptor.MediaType] {
			return registryIndexDescriptor{}, imagePlatform{}, errors.New("matching OCI image index descriptor has an unsupported mediaType")
		}
		candidates = append(candidates, candidate{descriptor: descriptor, platform: actual})
	}
	if len(candidates) == 0 {
		return registryIndexDescriptor{}, imagePlatform{}, fmt.Errorf("OCI image index does not contain platform %s", requested.String())
	}
	if len(candidates) != 1 {
		return registryIndexDescriptor{}, imagePlatform{}, fmt.Errorf("OCI image index contains %d ambiguous matches for platform %s", len(candidates), requested.String())
	}
	return candidates[0].descriptor, candidates[0].platform, nil
}

func fetchAuthorizedRegistryManifest(ctx context.Context, client *http.Client, reference registryReference, manifestReference string, allowed map[string]bool, directToken string) ([]byte, string, string, error) {
	manifestURL := "https://" + reference.Registry + "/v2/" + reference.Repository + "/manifests/" + url.PathEscape(manifestReference)
	body, declaredDigest, contentType, challenge, err := fetchRegistryManifest(ctx, client, manifestURL, directToken)
	if err != nil {
		return nil, "", "", err
	}
	if challenge != "" {
		if directToken != "" {
			return nil, "", "", errors.New("registry rejected the configured bearer token")
		}
		token, tokenErr := fetchRegistryChallengeToken(ctx, client, challenge, reference.Repository, allowed)
		if tokenErr != nil {
			return nil, "", "", tokenErr
		}
		body, declaredDigest, contentType, challenge, err = fetchRegistryManifest(ctx, client, manifestURL, token)
		if err != nil {
			return nil, "", "", err
		}
		if challenge != "" {
			return nil, "", "", errors.New("registry authentication did not authorize manifest access")
		}
	}
	digest, mediaType, err := verifyRegistryManifest(body, declaredDigest, contentType)
	if err != nil {
		return nil, "", "", err
	}
	return body, digest, mediaType, nil
}

func verifyRegistryManifest(body []byte, declaredDigest, contentType string) (string, string, error) {
	var manifest struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil || manifest.SchemaVersion != 2 {
		return "", "", errors.New("registry returned an invalid OCI or Docker v2 manifest")
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	if !supportedManifestMediaTypes[mediaType] {
		return "", "", errors.New("registry returned an unsupported manifest Content-Type")
	}
	if manifest.MediaType != "" && !strings.EqualFold(manifest.MediaType, mediaType) {
		return "", "", errors.New("registry manifest mediaType does not match its Content-Type")
	}
	sum := sha256.Sum256(body)
	computed := "sha256:" + hex.EncodeToString(sum[:])
	if declaredDigest == "" {
		return computed, mediaType, nil
	}
	declaredDigest = strings.ToLower(strings.TrimSpace(declaredDigest))
	if !ociDigestPattern.MatchString(declaredDigest) {
		return "", "", errors.New("registry returned an invalid Docker-Content-Digest header")
	}
	if declaredDigest != computed {
		return "", "", errors.New("registry manifest body does not match Docker-Content-Digest")
	}
	return declaredDigest, mediaType, nil
}

func isRegistryIndexMediaType(mediaType string) bool {
	return mediaType == "application/vnd.oci.image.index.v1+json" || mediaType == "application/vnd.docker.distribution.manifest.list.v2+json"
}

func isRegistryImageManifestMediaType(mediaType string) bool {
	return mediaType == "application/vnd.oci.image.manifest.v1+json" || mediaType == "application/vnd.docker.distribution.manifest.v2+json"
}

func fetchRegistryManifest(ctx context.Context, client *http.Client, manifestURL, token string) ([]byte, string, string, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return nil, "", "", "", err
	}
	request.Header.Set("User-Agent", "PatchRover/0.2 (+https://github.com/shubham23596/patchrover)")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
	}, ", "))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, "", "", "", fmt.Errorf("fetch OCI manifest: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized {
		// Drain the small error response so HTTP/2 registries can safely reuse the
		// authenticated connection for the manifest retry.
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxRegistryTokenBytes))
		challenge := response.Header.Get("WWW-Authenticate")
		if strings.TrimSpace(challenge) == "" {
			return nil, "", "", "", errors.New("registry returned HTTP 401 without an authentication challenge")
		}
		return nil, "", "", challenge, nil
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, "", "", "", fmt.Errorf("registry returned HTTP %d for manifest", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxRegistryManifestBytes+1))
	if err != nil {
		return nil, "", "", "", err
	}
	if len(body) > maxRegistryManifestBytes {
		return nil, "", "", "", errors.New("OCI manifest exceeds the 8 MiB safety limit")
	}
	return body, response.Header.Get("Docker-Content-Digest"), response.Header.Get("Content-Type"), "", nil
}

func fetchRegistryChallengeToken(ctx context.Context, client *http.Client, challenge, repository string, allowed map[string]bool) (string, error) {
	if len(challenge) > 8<<10 {
		return "", errors.New("registry authentication challenge exceeds the 8 KiB safety limit")
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(challenge)), "bearer ") {
		return "", errors.New("registry requires an unsupported authentication scheme")
	}
	parameters := map[string]string{}
	for _, match := range bearerParameter.FindAllStringSubmatch(challenge, -1) {
		parameters[strings.ToLower(match[1])] = match[2]
	}
	if len(parameters["realm"]) > 2048 || len(parameters["service"]) > 512 || len(parameters["scope"]) > 512 {
		return "", errors.New("registry authentication challenge contains an oversized parameter")
	}
	realm, err := url.Parse(parameters["realm"])
	if err != nil || realm.Scheme != "https" || realm.Host == "" || realm.User != nil || realm.Fragment != "" || !allowed[strings.ToLower(realm.Host)] {
		return "", errors.New("registry authentication realm is not on the explicit HTTPS host allowlist")
	}
	expectedScope := "repository:" + repository + ":pull"
	scope := parameters["scope"]
	if scope == "" {
		scope = expectedScope
	}
	if scope != expectedScope {
		return "", errors.New("registry requested a bearer-token scope other than the exact repository pull scope")
	}
	query := realm.Query()
	if service := parameters["service"]; service != "" {
		query.Set("service", service)
	}
	query.Set("scope", scope)
	realm.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "PatchRover/0.2 (+https://github.com/shubham23596/patchrover)")
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("fetch OCI registry bearer token: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", fmt.Errorf("registry token service returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxRegistryTokenBytes+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxRegistryTokenBytes {
		return "", errors.New("registry token response exceeds the 64 KiB safety limit")
	}
	var result struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", errors.New("decode registry bearer token response")
	}
	token := result.Token
	if token == "" {
		token = result.AccessToken
	}
	if token == "" || len(token) > 16<<10 || strings.ContainsAny(token, "\r\n\x00") {
		return "", errors.New("registry token service returned an invalid bearer token")
	}
	return token, nil
}
