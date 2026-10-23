package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shubham23596/patchrover/internal/collect"
	"github.com/shubham23596/patchrover/internal/model"
)

func TestConfigRejectsUnallowlistedAndInsecureEndpoints(t *testing.T) {
	config := validConfig(t.TempDir())
	config.Sources = []Source{{ID: "kev", Kind: "cisa-kev", URL: "http://example.com/kev.json"}}
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected HTTPS rejection, got %v", err)
	}
	config.Sources[0].URL = "https://not-allowed.example/kev.json"
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("expected host rejection, got %v", err)
	}
}

func TestConfigRequiresProposeModeForCommercialControlPlane(t *testing.T) {
	config := validConfig(t.TempDir())
	config.Integrations.ControlPlane = &ControlPlaneConfig{URL: "https://control.example", TokenEnv: "PATCHROVER_CONTROL_PLANE_TOKEN"}
	config.AllowedHosts = append(config.AllowedHosts, "control.example")
	if err := config.Validate(); err != nil {
		t.Fatalf("commercial integration was rejected: %v", err)
	}
	config.Mode = "observe"
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "propose mode") {
		t.Fatalf("observe-mode commercial integration returned %v", err)
	}
}

func TestConfigRejectsRemovedLocalWriteIntegration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	data := []byte(`{"apiVersion":"patchrover.dev/agent/v1alpha1","mode":"propose","interval":"5m","statePath":"state.json","allowedHosts":[],"targets":[],"policy":{"maxActionsPerRun":1},"integrations":{"github":{"apiBase":"https://api.github.com","tokenEnv":"PATCHROVER_GITHUB_TOKEN"}}}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("removed local write integration returned %v", err)
	}
}

func TestFeedParsers(t *testing.T) {
	cisa, err := parseCISA([]byte(`{"vulnerabilities":[{"cveID":"CVE-2026-1","vulnerabilityName":"Example","dateAdded":"2026-10-01"}]}`), Source{ID: "cisa", URL: "https://example.com"})
	if err != nil || len(cisa) != 1 || cisa[0].Severity != "known-exploited" {
		t.Fatalf("unexpected CISA result %#v, %v", cisa, err)
	}
	github, err := parseGitHubAdvisories([]byte(`[{"ghsa_id":"GHSA-1","cve_id":null,"summary":"Example","severity":"high","published_at":"2026-10-01T00:00:00Z","html_url":"https://example.com/a"}]`), Source{ID: "github"})
	if err != nil || len(github) != 1 || github[0].ID != "GHSA-1" {
		t.Fatalf("unexpected GitHub result %#v, %v", github, err)
	}
	rss, err := parseRSS([]byte(`<rss><channel><item><title>Security update</title><link>https://example.com/x</link><guid>x</guid><pubDate>today</pubDate></item></channel></rss>`), Source{ID: "rss"})
	if err != nil || len(rss) != 1 || rss[0].Title != "Security update" {
		t.Fatalf("unexpected RSS result %#v, %v", rss, err)
	}
}

func TestRunOncePersistsSourceHealthAndFirstObservation(t *testing.T) {
	failing := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if failing {
			http.Error(writer, "temporary upstream failure", http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`[{"ghsa_id":"GHSA-1","cve_id":null,"summary":"Example","severity":"high","published_at":"2026-10-01T00:00:00Z","html_url":"https://example.com/a"}]`))
	}))
	defer server.Close()

	config := validConfig(t.TempDir())
	config.AllowedHosts = append(config.AllowedHosts, "127.0.0.1")
	config.Sources = []Source{{ID: "github", Kind: "github-advisories", URL: server.URL}}
	runner := Runner{FeedClient: FeedClient{HTTP: server.Client()}}
	if _, err := runner.RunOnce(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	state, err := LoadState(config.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Sources) != 1 || state.Sources[0].LastSuccessAt == "" || state.Sources[0].LastError != "" || state.Sources[0].AdvisoryCount != 1 {
		t.Fatalf("unexpected successful source status: %#v", state.Sources)
	}
	if len(state.Advisories) != 1 || state.Advisories[0].ObservedAt == "" {
		t.Fatalf("first observation was not retained: %#v", state.Advisories)
	}
	firstObservedAt := state.Advisories[0].ObservedAt
	firstSuccessAt := state.Sources[0].LastSuccessAt

	failing = true
	if _, err := runner.RunOnce(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	state, err = LoadState(config.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.Sources[0].LastError == "" || state.Sources[0].LastSuccessAt != firstSuccessAt {
		t.Fatalf("source failure did not preserve the last success: %#v", state.Sources[0])
	}
	if len(state.Advisories) != 1 || state.Advisories[0].ObservedAt != firstObservedAt {
		t.Fatalf("source failure discarded or rewrote advisory history: %#v", state.Advisories)
	}
}

func TestRetainNewestAdvisoriesUsesPublishedThenObservedTime(t *testing.T) {
	items := []Advisory{
		{ID: "old", Source: "a", PublishedAt: "2026-01-01"},
		{ID: "new", Source: "a", PublishedAt: "Thu, 22 Oct 2026 10:00:00 GMT"},
		{ID: "observed", Source: "b", PublishedAt: "not-a-date", ObservedAt: "2026-10-23T10:00:00Z"},
	}
	retained := retainNewestAdvisories(items, 2)
	if len(retained) != 2 || retained[0].ID != "observed" || retained[1].ID != "new" {
		t.Fatalf("did not retain the newest advisories: %#v", retained)
	}
}

func TestActionStatePrunesOnlyReadOnlyObservationsAndFailsClosedAtLimit(t *testing.T) {
	state := NewState()
	state.Actions = []Action{{ID: "observation", Status: "observed"}, {ID: "approval", Status: "submitted"}, {ID: "pending", Status: "pending"}}
	if removed := state.pruneStaleObservedActions(map[string]bool{}); removed != 1 || len(state.Actions) != 2 {
		t.Fatalf("unexpected action pruning: removed=%d actions=%#v", removed, state.Actions)
	}
	for _, action := range state.Actions {
		if action.Status == "observed" {
			t.Fatal("read-only observation was not pruned")
		}
	}
	state.Actions = make([]Action, maxStateActions)
	if added, err := state.addAction(Action{ID: "new"}); err == nil || added {
		t.Fatalf("action state did not fail closed at its hard limit: added=%t err=%v", added, err)
	}
}

func TestAuditTamperingFails(t *testing.T) {
	state := NewState()
	state.AppendAudit("test", "", "original")
	if err := state.VerifyAudit(); err != nil {
		t.Fatal(err)
	}
	state.Audit[0].Detail = "tampered"
	if err := state.VerifyAudit(); err == nil {
		t.Fatal("expected tampered audit chain to fail")
	}
}

func TestRunOnceQueuesReadOnlyProposalsWithoutExecution(t *testing.T) {
	directory := t.TempDir()
	repository := filepath.Join(directory, "repo")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "requirements.txt"), []byte("litellm==1.107.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := validConfig(directory)
	config.Targets[0].Evidence.RepositoryPath = repository
	config.Targets[0].Pack = filepath.Join("..", "..", "packs", "litellm-1.107.0-compromise")
	config.Targets[0].GitHubRepository = "acme/service"
	config.Targets[0].BaseBranch = "main"
	config.Targets[0].VaultDatabaseRotations = []string{"service-db"}
	report, err := (Runner{}).RunOnce(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if report.ActionsCreated != 2 {
		t.Fatalf("unexpected report %+v", report)
	}
	state, err := LoadState(config.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Actions) != 2 || state.Actions[0].Status != "pending" {
		t.Fatalf("unexpected actions %#v", state.Actions)
	}
	if _, err := (Runner{}).RunOnce(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	state, _ = LoadState(config.StatePath)
	if state.Actions[0].Status != "pending" {
		t.Fatalf("open-source agent changed a proposed action: %#v", state.Actions[0])
	}
}

func TestRunOnceSubmitsBoundedActionsToCommercialApprovalInbox(t *testing.T) {
	directory := t.TempDir()
	repository := filepath.Join(directory, "repo")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "requirements.txt"), []byte("litellm==1.107.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var submissions []map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/agent/actions" {
			http.Error(writer, "unexpected endpoint", http.StatusNotFound)
			return
		}
		if request.Header.Get("Authorization") != "Bearer commercial-runner-token" {
			http.Error(writer, "missing token", http.StatusUnauthorized)
			return
		}
		var submission map[string]any
		if err := json.NewDecoder(request.Body).Decode(&submission); err != nil {
			t.Error(err)
			http.Error(writer, "bad JSON", http.StatusBadRequest)
			return
		}
		encoded, _ := json.Marshal(submission)
		if bytes.Contains(encoded, []byte("litellm==1.107.0")) || bytes.Contains(encoded, []byte("commercial-runner-token")) {
			t.Error("repository content or token reached the control plane payload")
		}
		submissions = append(submissions, submission)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(writer).Encode(map[string]string{"id": fmt.Sprintf("remote-%d", len(submissions)), "status": "pending"}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	t.Setenv("PATCHROVER_CONTROL_PLANE_TOKEN", "commercial-runner-token")
	config := validConfig(directory)
	config.AllowedHosts = append(config.AllowedHosts, "127.0.0.1")
	config.Integrations = Integrations{ControlPlane: &ControlPlaneConfig{URL: server.URL, TokenEnv: "PATCHROVER_CONTROL_PLANE_TOKEN"}}
	config.Targets[0].Evidence.RepositoryPath = repository
	config.Targets[0].Pack = filepath.Join("..", "..", "packs", "litellm-1.107.0-compromise")
	config.Targets[0].GitHubRepository = "acme/service"
	config.Targets[0].BaseBranch = "main"
	config.Targets[0].VaultDatabaseRotations = []string{"service-db"}
	runner := Runner{ControlPlaneHTTP: server.Client()}
	report, err := runner.RunOnce(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if report.ActionsCreated != 2 || report.ActionsSubmitted != 2 || report.SubmissionErrors != 0 || len(submissions) != 2 {
		t.Fatalf("unexpected submission report %+v payloads=%d", report, len(submissions))
	}
	state, err := LoadState(config.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range state.Actions {
		if action.Status != "submitted" || action.ControlPlaneActionID == "" || action.TrailID == "" {
			t.Fatalf("action was not bound to commercial approval: %#v", action)
		}
	}
	if _, err := runner.RunOnce(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if len(submissions) != 2 {
		t.Fatalf("submitted actions were sent again: %d payloads", len(submissions))
	}
}

func TestCommercialActionsSplitMultiFileChanges(t *testing.T) {
	action := Action{ID: "combined", Type: ActionGitHubPullRequest, Changes: []model.RemediationChange{
		{Path: "go.mod", BeforeSHA256: strings.Repeat("a", 64), OldVersion: "1", NewVersion: "2"},
		{Path: "go.sum", BeforeSHA256: strings.Repeat("b", 64), OldVersion: "1", NewVersion: "2"},
	}}
	bounded := splitCommercialActions([]Action{action})
	if len(bounded) != 2 || len(bounded[0].Changes) != 1 || len(bounded[1].Changes) != 1 || bounded[0].ID == bounded[1].ID {
		t.Fatalf("multi-file action was not split into deterministic bounded actions: %#v", bounded)
	}
}

func TestAssessTargetReportsSourceToRuntimeDrift(t *testing.T) {
	root := filepath.Join("..", "..", "packs", "php-2026-rce")
	fixture := filepath.Join(root, "fixtures", "drift")
	result, _, err := assessTarget(Target{
		ID:   "php-runtime",
		Pack: root,
		Evidence: collect.Options{
			RepositoryPath: fixture,
			KubeSnapshot:   filepath.Join(fixture, "pods.json"),
		},
	}, "observe")
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != model.VerdictAffected || !result.Drift {
		t.Fatalf("drift result was not preserved: %#v", result)
	}
}

func validConfig(directory string) Config {
	return Config{
		APIVersion: ConfigVersion, Mode: "propose", Interval: "5m", StatePath: filepath.Join(directory, "state.json"),
		AllowedHosts: []string{"api.github.com"},
		Targets:      []Target{{ID: "service", Pack: "pack", Evidence: collect.Options{ImageReference: "example:v1"}}},
		Policy:       Policy{MaxActionsPerRun: 2},
	}
}
