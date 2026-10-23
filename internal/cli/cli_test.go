package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shubham23596/patchrover/internal/agent"
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

func TestAgentReviewRequiresTypedYes(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "state.json")
	state := agent.NewState()
	state.Actions = []agent.Action{{
		ID: "action-123", Type: agent.ActionGitHubPullRequest, TargetID: "service", PackID: "incident-pack",
		Status: "pending", Repository: "acme/service", BaseBranch: "main",
	}}
	if err := agent.SaveState(statePath, state); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "agent.json")
	config := map[string]any{
		"apiVersion":   agent.ConfigVersion,
		"mode":         "propose",
		"interval":     "5m",
		"statePath":    statePath,
		"allowedHosts": []string{},
		"targets": []any{map[string]any{
			"id": "service", "pack": "unused-pack", "evidence": map[string]any{"imageReference": "example:v1"},
		}},
		"policy": map[string]any{"maxActionsPerRun": 1},
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := RunWithInput([]string{"agent", "review", "--config", configPath, "--action", "action-123"}, strings.NewReader("no\n"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("review failed: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "FIX REQUIRES APPROVAL") || !strings.Contains(stdout.String(), "CANCELLED") {
		t.Fatalf("review did not show and cancel the action: %s", stdout.String())
	}
	state, err = agent.LoadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.Actions[0].Status != "pending" {
		t.Fatalf("cancelled review changed action status to %q", state.Actions[0].Status)
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
