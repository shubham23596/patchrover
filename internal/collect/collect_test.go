package collect

import (
	"os"
	"path/filepath"
	"strings"
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
