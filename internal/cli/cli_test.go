package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shubham23596/patchrover/internal/agent"
	"github.com/shubham23596/patchrover/internal/model"
)

func TestPackValidateIncludesGoldenFixtures(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"pack", "validate", filepath.Join("..", "..", "packs", "php-2026-rce")}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("pack validation failed: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "FIXTURES  affected, fixed, drift, and unknown corpus passed") {
		t.Fatalf("fixture result missing: %s", stdout.String())
	}
}

func TestAgentReviewCommandIsNotAvailableInOpenSourceBinary(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := RunWithInput([]string{"agent", "review"}, strings.NewReader("yes\n"), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "agent run|status") {
		t.Fatalf("removed write command returned code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestAgentStatusShowsSourceHealthAndRuntimeDrift(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	state := agent.NewState()
	state.Sources = []agent.SourceStatus{{ID: "github", LastAttemptAt: "2026-10-23T10:00:00Z", LastSuccessAt: "2026-10-23T09:00:00Z", AdvisoryCount: 12, LastError: "HTTP 503"}}
	state.Targets = []agent.TargetResult{{ID: "api", Verdict: model.VerdictAffected, Drift: true, TrailID: "trail-1"}}
	state.AppendAudit("test", "", "status fixture")
	if err := agent.SaveState(path, state); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Run([]string{"agent", "status", "--state", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("status failed code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "SOURCE github health=error") || !strings.Contains(stdout.String(), "TARGET api verdict=affected drift=true") {
		t.Fatalf("source health or drift missing from status:\n%s", stdout.String())
	}
}

func TestFixtureSafetyRejectsExecutableContent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "run.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateFixtureSafety(root); err == nil {
		t.Fatal("executable fixture unexpectedly passed")
	}
}

func TestWriteFileRejectsSymlinkOutput(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "output")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(link, []byte("replace"), true); err == nil {
		t.Fatal("symlink output unexpectedly accepted")
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "preserve" {
		t.Fatalf("symlink target was modified: %q", data)
	}
}
