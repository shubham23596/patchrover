package collect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPythonLockEvidenceUsesVersionLine(t *testing.T) {
	root := t.TempDir()
	content := "[[package]]\nname = \"litellm\"\nversion = \"1.107.0\"\n"
	if err := os.WriteFile(filepath.Join(root, "poetry.lock"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	evidence, err := Repository(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 1 || !strings.HasSuffix(evidence[0].Location, "poetry.lock:3") {
		t.Fatalf("expected exact version line, got %#v", evidence)
	}
}

func TestKubernetesSnapshotWithoutImmutableDigestStaysExplicit(t *testing.T) {
	document := []byte(`{"items":[{"metadata":{"namespace":"sample","name":"app"},"spec":{"containers":[{"name":"app","image":"php:8.4.27-apache"}]}}]}`)
	evidence, err := KubernetesSnapshot(document, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 1 || evidence[0].Digest != "" || !evidence[0].Runtime {
		t.Fatalf("unexpected evidence: %#v", evidence)
	}
	if !strings.Contains(evidence[0].Detail, "without runtime digest") {
		t.Fatalf("missing mutable-tag warning: %q", evidence[0].Detail)
	}
}

func TestKubernetesUsesFixedReadOnlyCommand(t *testing.T) {
	root := t.TempDir()
	argumentsPath := filepath.Join(root, "arguments.txt")
	snapshotPath := filepath.Join(root, "pods.json")
	snapshot := `{"apiVersion":"v1","kind":"PodList","items":[{"metadata":{"namespace":"synthetic","name":"api"},"spec":{"containers":[{"name":"app","image":"php:8.4.27-apache"}]},"status":{"containerStatuses":[{"name":"app","image":"php:8.4.27-apache","imageID":"docker-pullable://example.invalid/php@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}}]}`
	if err := os.WriteFile(snapshotPath, []byte(snapshot), 0o600); err != nil {
		t.Fatal(err)
	}
	kubectlPath := filepath.Join(root, "kubectl")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$PATCHROVER_ARGS\"\nexec /bin/cat \"$PATCHROVER_SNAPSHOT\"\n"
	if err := os.WriteFile(kubectlPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	t.Setenv("PATCHROVER_ARGS", argumentsPath)
	t.Setenv("PATCHROVER_SNAPSHOT", snapshotPath)
	evidence, err := Kubernetes("approved-context")
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 1 || !evidence[0].Runtime {
		t.Fatalf("unexpected Kubernetes evidence: %#v", evidence)
	}
	arguments, err := os.ReadFile(argumentsPath)
	if err != nil {
		t.Fatal(err)
	}
	expected := "--context\napproved-context\nget\npods\n--all-namespaces\n-o\njson\n--request-timeout=15s\n"
	if string(arguments) != expected {
		t.Fatalf("kubectl arguments = %q, want %q", arguments, expected)
	}
	if strings.Contains(string(arguments), "exec") || strings.Contains(string(arguments), "secret") {
		t.Fatalf("unsafe Kubernetes operation in arguments: %q", arguments)
	}
}

func TestResolveImageReferenceUsesScopedBearerChallengeAndVerifiesDigest(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":2},"layers":[]}`)
	sum := sha256.Sum256(manifest)
	wantDigest := "sha256:" + hex.EncodeToString(sum[:])
	var usedHTTP2 atomic.Bool
	var server *httptest.Server
	server = httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.ProtoMajor == 2 {
			usedHTTP2.Store(true)
		}
		switch request.URL.Path {
		case "/token":
			if request.URL.Query().Get("scope") != "repository:org/app:pull" || request.URL.Query().Get("service") != "registry.test" {
				t.Errorf("unexpected token query: %s", request.URL.RawQuery)
			}
			_ = json.NewEncoder(writer).Encode(map[string]string{"token": "scoped-read-token"})
		case "/v2/org/app/manifests/1.2.3":
			if request.Header.Get("Authorization") != "Bearer scoped-read-token" {
				writer.Header().Set("WWW-Authenticate", `Bearer realm="`+server.URL+`/token",service="registry.test",scope="repository:org/app:pull"`)
				http.Error(writer, "authorization required", http.StatusUnauthorized)
				return
			}
			writer.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			writer.Header().Set("Docker-Content-Digest", wantDigest)
			_, _ = writer.Write(manifest)
		default:
			http.NotFound(writer, request)
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "https://")
	item, err := ResolveImageReference(context.Background(), host+"/org/app:1.2.3", "image-under-test", false, RegistryOptions{AllowedHosts: []string{host}, HTTP: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if item.Digest != wantDigest || item.Confidence != "high" || item.Version != "1.2.3" || !strings.Contains(item.Detail, "verified") {
		t.Fatalf("unexpected resolved image evidence: %#v", item)
	}
	if !usedHTTP2.Load() {
		t.Fatal("bearer challenge path was not exercised over HTTP/2")
	}
}

func TestResolveImageReferenceSelectsAndVerifiesPlatformManifest(t *testing.T) {
	armManifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":2},"layers":[]}`)
	amdManifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":2},"layers":[]}`)
	armSum := sha256.Sum256(armManifest)
	amdSum := sha256.Sum256(amdManifest)
	armDigest := "sha256:" + hex.EncodeToString(armSum[:])
	amdDigest := "sha256:" + hex.EncodeToString(amdSum[:])
	index, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests": []any{
			map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": amdDigest, "size": len(amdManifest), "platform": map[string]any{"os": "linux", "architecture": "amd64"}},
			map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": armDigest, "size": len(armManifest), "platform": map[string]any{"os": "linux", "architecture": "arm64", "variant": "v8"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	indexSum := sha256.Sum256(index)
	indexDigest := "sha256:" + hex.EncodeToString(indexSum[:])
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		switch request.URL.Path {
		case "/v2/org/app/manifests/2.0":
			writer.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
			writer.Header().Set("Docker-Content-Digest", indexDigest)
			_, _ = writer.Write(index)
		case "/v2/org/app/manifests/" + armDigest:
			writer.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			writer.Header().Set("Docker-Content-Digest", armDigest)
			_, _ = writer.Write(armManifest)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "https://")
	item, err := ResolveImageReference(context.Background(), host+"/org/app:2.0", "image-under-test", true, RegistryOptions{AllowedHosts: []string{host}, Platform: "linux/arm64/v8", HTTP: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if item.Digest != armDigest || item.IndexDigest != indexDigest || item.Platform != "linux/arm64/v8" || !item.Runtime {
		t.Fatalf("unexpected platform evidence: %#v", item)
	}
	if requests != 2 {
		t.Fatalf("platform selection made %d registry requests, want index plus one child", requests)
	}
}

func TestResolveImageReferenceRejectsAmbiguousOrUnverifiedPlatform(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`)
	manifestSum := sha256.Sum256(manifest)
	manifestDigest := "sha256:" + hex.EncodeToString(manifestSum[:])
	index, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests": []any{
			map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifestDigest, "size": len(manifest), "platform": map[string]any{"os": "linux", "architecture": "arm64", "variant": "v8"}},
			map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + strings.Repeat("b", 64), "size": len(manifest), "platform": map[string]any{"os": "linux", "architecture": "arm64", "variant": "v9"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	indexSum := sha256.Sum256(index)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
		writer.Header().Set("Docker-Content-Digest", "sha256:"+hex.EncodeToString(indexSum[:]))
		_, _ = writer.Write(index)
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "https://")
	_, err = ResolveImageReference(context.Background(), host+"/org/app:2.0", "image", false, RegistryOptions{AllowedHosts: []string{host}, Platform: "linux/arm64", HTTP: server.Client()})
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous platform selection returned %v", err)
	}

	directManifestServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		writer.Header().Set("Docker-Content-Digest", manifestDigest)
		_, _ = writer.Write(manifest)
	}))
	defer directManifestServer.Close()
	directHost := strings.TrimPrefix(directManifestServer.URL, "https://")
	_, err = ResolveImageReference(context.Background(), directHost+"/org/app:2.0", "image", false, RegistryOptions{AllowedHosts: []string{directHost}, Platform: "linux/arm64/v8", HTTP: directManifestServer.Client()})
	if err == nil || !strings.Contains(err.Error(), "cannot be proven") {
		t.Fatalf("unverifiable direct manifest platform returned %v", err)
	}
}

func TestResolveImageReferenceRejectsPlatformDescriptorBodyMismatch(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`)
	declaredDigest := "sha256:" + strings.Repeat("a", 64)
	index, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests": []any{
			map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": declaredDigest, "size": len(manifest), "platform": map[string]any{"os": "linux", "architecture": "amd64"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	indexSum := sha256.Sum256(index)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/1.0") {
			writer.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
			writer.Header().Set("Docker-Content-Digest", "sha256:"+hex.EncodeToString(indexSum[:]))
			_, _ = writer.Write(index)
			return
		}
		writer.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		_, _ = writer.Write(manifest)
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "https://")
	_, err = ResolveImageReference(context.Background(), host+"/org/app:1.0", "image", false, RegistryOptions{AllowedHosts: []string{host}, Platform: "linux/amd64", HTTP: server.Client()})
	if err == nil || !strings.Contains(err.Error(), "descriptor digest") {
		t.Fatalf("descriptor body mismatch returned %v", err)
	}
}

func TestResolveImageReferenceRejectsUnallowlistedNetworkAndDigestMismatch(t *testing.T) {
	requests := 0
	manifest := []byte(`{"schemaVersion":2}`)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		writer.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		writer.Header().Set("Docker-Content-Digest", "sha256:"+strings.Repeat("f", 64))
		_, _ = writer.Write(manifest)
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "https://")
	reference := host + "/org/app:latest"
	if _, err := ResolveImageReference(context.Background(), reference, "image", false, RegistryOptions{AllowedHosts: []string{"registry.example"}, HTTP: server.Client()}); err == nil || !strings.Contains(err.Error(), "not explicitly allowlisted") {
		t.Fatalf("unallowlisted registry returned %v", err)
	}
	if requests != 0 {
		t.Fatalf("unallowlisted registry received %d requests", requests)
	}
	if _, err := ResolveImageReference(context.Background(), reference, "image", false, RegistryOptions{AllowedHosts: []string{host}, HTTP: server.Client()}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("digest mismatch returned %v", err)
	}
}

func TestResolveImageReferenceAcceptsPinnedAndBareDigestsWithoutNetwork(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, reference := range []string{"ghcr.io/acme/app@" + digest, digest} {
		item, err := ResolveImageReference(context.Background(), reference, "image", false, RegistryOptions{})
		if err != nil {
			t.Fatalf("pinned reference %q failed: %v", reference, err)
		}
		if item.Digest != digest || item.Confidence != "high" {
			t.Fatalf("unexpected pinned evidence for %q: %#v", reference, item)
		}
	}
}

func TestResolveImageReferenceRejectsUnallowlistedAuthenticationRealm(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("WWW-Authenticate", `Bearer realm="https://auth.example/token",service="registry.test",scope="repository:org/app:pull"`)
		http.Error(writer, "authorization required", http.StatusUnauthorized)
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "https://")
	_, err := ResolveImageReference(context.Background(), host+"/org/app:latest", "image", false, RegistryOptions{AllowedHosts: []string{host}, HTTP: server.Client()})
	if err == nil || !strings.Contains(err.Error(), "authentication realm") {
		t.Fatalf("unallowlisted authentication realm returned %v", err)
	}
}

func TestResolveImageReferenceRejectsManifestMediaTypeMismatch(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json"}`)
	sum := sha256.Sum256(manifest)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		writer.Header().Set("Docker-Content-Digest", "sha256:"+hex.EncodeToString(sum[:]))
		_, _ = writer.Write(manifest)
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "https://")
	_, err := ResolveImageReference(context.Background(), host+"/org/app:latest", "image", false, RegistryOptions{AllowedHosts: []string{host}, HTTP: server.Client()})
	if err == nil || !strings.Contains(err.Error(), "mediaType does not match") {
		t.Fatalf("manifest media type mismatch returned %v", err)
	}
}

func TestResolveImageReferenceUsesEnvironmentTokenWithoutPersistingIt(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2}`)
	sum := sha256.Sum256(manifest)
	wantDigest := "sha256:" + hex.EncodeToString(sum[:])
	t.Setenv("PATCHROVER_TEST_REGISTRY_TOKEN", "private-read-token")
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer private-read-token" {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		writer.Header().Set("Docker-Content-Digest", wantDigest)
		_, _ = writer.Write(manifest)
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "https://")
	item, err := ResolveImageReference(context.Background(), host+"/org/private:stable", "image", false, RegistryOptions{AllowedHosts: []string{host}, TokenEnv: "PATCHROVER_TEST_REGISTRY_TOKEN", HTTP: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	if item.Digest != wantDigest || strings.Contains(string(encoded), "private-read-token") {
		t.Fatalf("private registry result leaked or lost evidence: %s", encoded)
	}
}

func TestAllRequiresResolutionForRegistrySettings(t *testing.T) {
	_, err := All(Options{ImageReference: "ghcr.io/acme/app:latest", RegistryAllowedHosts: []string{"ghcr.io"}})
	if err == nil || !strings.Contains(err.Error(), "require live image resolution") {
		t.Fatalf("unused registry settings returned %v", err)
	}
	_, err = All(Options{RepositoryPath: t.TempDir(), ResolveImage: true})
	if err == nil || !strings.Contains(err.Error(), "requires an explicit image") {
		t.Fatalf("resolution without an image returned %v", err)
	}
	_, err = All(Options{ImageReference: "ghcr.io/acme/app:latest", ImagePlatform: "linux/amd64"})
	if err == nil || !strings.Contains(err.Error(), "platform selection requires") {
		t.Fatalf("platform selection without resolution returned %v", err)
	}
	if err := ValidateRegistryResolution("ghcr.io/acme/app:latest", RegistryOptions{AllowedHosts: []string{"ghcr.io"}, Platform: "windows/amd64"}); err == nil || !strings.Contains(err.Error(), "Linux") {
		t.Fatalf("unsupported operating system returned %v", err)
	}
	if err := ValidateRegistryResolution("ghcr.io/acme/app@sha256:"+strings.Repeat("a", 64), RegistryOptions{Platform: "linux/amd64"}); err == nil || !strings.Contains(err.Error(), "tagged reference") {
		t.Fatalf("platform selection for pinned digest returned %v", err)
	}
}

func TestDefaultRegistryClientHasABoundedTimeout(t *testing.T) {
	client := restrictedRegistryHTTPClient(nil, map[string]bool{"registry.example": true})
	if client.Timeout <= 0 {
		t.Fatalf("default registry client has no timeout: %#v", client)
	}
}
