package proposal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shubham23596/patchrover/internal/model"
)

func TestSafeRepositoryPathRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "requirements.txt")
	if err := os.WriteFile(outside, []byte("litellm==1.107.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "requirements.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if path, ok := safeRepositoryPath(root, "requirements.txt"); ok {
		t.Fatalf("expected symlink escape to be rejected, got %q", path)
	}
}

func TestSafeRepositoryPathAcceptsRegularFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "requirements.txt")
	if err := os.WriteFile(path, []byte("litellm==1.107.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, ok := safeRepositoryPath(root, "requirements.txt")
	if !ok {
		t.Fatal("expected regular repository file to be accepted")
	}
	expected, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != expected {
		t.Fatalf("resolved path = %q, want %q", resolved, expected)
	}
}

func TestReplaceVersionChangesOnlyEvidenceLine(t *testing.T) {
	content := "litellm==1.107.0\nother==1.107.0\nlitellm==1.107.0\n"
	evidence := model.EvidenceRef{Collector: "requirements", Name: "litellm", Version: "1.107.0"}
	updated, changed := replaceVersion(content, evidence, "1.106.2", 3)
	if !changed {
		t.Fatal("expected safe replacement")
	}
	want := "litellm==1.107.0\nother==1.107.0\nlitellm==1.106.2\n"
	if updated != want {
		t.Fatalf("unexpected replacement:\n%s", updated)
	}
}

func TestReplaceVersionPreservesDockerTagSuffix(t *testing.T) {
	content := "FROM php:8.4.26-apache\n"
	evidence := model.EvidenceRef{Collector: "dockerfile", Name: "php", Version: "8.4.26-apache"}
	updated, changed := replaceVersion(content, evidence, "8.4.27", 1)
	if !changed || !strings.Contains(updated, "php:8.4.27-apache") {
		t.Fatalf("unexpected Dockerfile replacement: %q", updated)
	}
}

func TestReplaceVersionRefusesWrongLine(t *testing.T) {
	content := "litellm==1.107.0\nother==2.0.0\n"
	evidence := model.EvidenceRef{Collector: "requirements", Name: "litellm", Version: "1.107.0"}
	updated, changed := replaceVersion(content, evidence, "1.106.2", 2)
	if changed || updated != content {
		t.Fatal("replacement ignored the evidence line")
	}
}

func TestApplyChangeRejectsStaleContent(t *testing.T) {
	change := model.RemediationChange{
		Path: "requirements.txt", OldVersion: "1.107.0", NewVersion: "1.106.2",
		Package: "litellm", Collector: "requirements", Line: 1,
		BeforeSHA256: contentSHA256([]byte("litellm==1.107.0\n")),
	}
	updated, err := ApplyChange([]byte("litellm==1.107.0\n"), change)
	if err != nil || string(updated) != "litellm==1.106.2\n" {
		t.Fatalf("apply bounded change: updated=%q err=%v", updated, err)
	}
	if _, err := ApplyChange([]byte("litellm==1.107.0\n# changed\n"), change); err == nil {
		t.Fatal("stale content unexpectedly accepted")
	}
}
