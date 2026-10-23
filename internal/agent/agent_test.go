package agent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

func TestVaultRotationUsesExactBoundedEndpoint(t *testing.T) {
	var gotPath, gotToken string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		gotPath, gotToken = request.URL.Path, request.Header.Get("X-Vault-Token")
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := VaultClient{Address: server.URL, Token: "secret-test-token", HTTP: server.Client(), AllowHTTP: true}
	if err := client.RotateDatabaseRoot(context.Background(), "payments-prod"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/database/rotate-root/payments-prod" || gotToken != "secret-test-token" {
		t.Fatalf("unexpected request path=%q token=%q", gotPath, gotToken)
	}
	if err := client.RotateDatabaseRoot(context.Background(), "../../human-password"); err == nil {
		t.Fatal("expected unsafe resource name to fail")
	}
}

func TestGitHubClientCreatesBoundedPullRequest(t *testing.T) {
	before := []byte("litellm==1.107.0\n")
	sum := sha256.Sum256(before)
	change := model.RemediationChange{Path: "requirements.txt", OldVersion: "1.107.0", NewVersion: "1.106.2", Package: "litellm", Collector: "requirements", Line: 1, BeforeSHA256: hex.EncodeToString(sum[:])}
	var updated []byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatal("missing GitHub bearer token")
		}
		switch {
		case request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/git/ref/"):
			writeJSONResponse(t, writer, map[string]any{"object": map[string]string{"sha": "base-sha"}})
		case request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/contents/"):
			writeJSONResponse(t, writer, map[string]string{"sha": "file-sha", "encoding": "base64", "content": base64.StdEncoding.EncodeToString(before)})
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/git/refs"):
			writeJSONResponse(t, writer, map[string]string{"ref": "ok"})
		case request.Method == http.MethodPut && strings.Contains(request.URL.Path, "/contents/"):
			var body map[string]string
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			updated, _ = base64.StdEncoding.DecodeString(body["content"])
			writeJSONResponse(t, writer, map[string]string{"sha": "new-sha"})
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/pulls"):
			writeJSONResponse(t, writer, map[string]string{"html_url": "https://github.com/acme/service/pull/1"})
		default:
			http.Error(writer, "unexpected", http.StatusNotFound)
		}
	}))
	defer server.Close()
	action := Action{ID: "1234567890abcdef", Type: ActionGitHubPullRequest, PackID: "litellm-pack", Repository: "acme/service", BaseBranch: "main", Changes: []model.RemediationChange{change}}
	url, err := (GitHubClient{BaseURL: server.URL, Token: "test-token", HTTP: server.Client(), AllowHTTP: true}).OpenRemediationPullRequest(context.Background(), action)
	if err != nil {
		t.Fatal(err)
	}
	if url != "https://github.com/acme/service/pull/1" || string(updated) != "litellm==1.106.2\n" {
		t.Fatalf("unexpected URL or content: %q %q", url, updated)
	}
}

func TestRunOnceQueuesActionsAndApproval(t *testing.T) {
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
	if err := Approve(config.StatePath, state.Actions[0].ID); err != nil {
		t.Fatal(err)
	}
	state, _ = LoadState(config.StatePath)
	if state.Actions[0].Status != "approved" {
		t.Fatal("approval was not persisted")
	}
	if _, err := (Runner{}).RunOnce(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	state, _ = LoadState(config.StatePath)
	if state.Actions[0].Status != "approved" {
		t.Fatalf("background assessment executed an approved action: %#v", state.Actions[0])
	}
}

func TestApplyApprovedFailsClosedAndRecordsOutcome(t *testing.T) {
	directory := t.TempDir()
	config := validConfig(directory)
	config.Integrations = Integrations{}
	state := NewState()
	state.Actions = []Action{{
		ID: "approved-action", Type: ActionGitHubPullRequest, TargetID: "service", PackID: "incident-pack",
		Status: "approved", Repository: "acme/service", BaseBranch: "main",
	}}
	if err := SaveState(config.StatePath, state); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyApproved(context.Background(), config, "approved-action"); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("expected a closed failure for a missing integration, got %v", err)
	}
	state, err := LoadState(config.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.Actions[0].Status != "failed" || len(state.Audit) != 2 || state.Audit[0].Event != "action_started" || state.Audit[1].Event != "action_failed" {
		t.Fatalf("unexpected failed action state %#v", state)
	}
}

func validConfig(directory string) Config {
	return Config{
		APIVersion: ConfigVersion, Mode: "propose", Interval: "5m", StatePath: filepath.Join(directory, "state.json"),
		AllowedHosts: []string{"api.github.com", "vault.example"},
		Targets:      []Target{{ID: "service", Pack: "pack", Evidence: collect.Options{ImageReference: "example:v1"}}},
		Policy:       Policy{MaxActionsPerRun: 2},
		Integrations: Integrations{
			GitHub: &GitHubConfig{APIBase: "https://api.github.com", TokenEnv: "PATCHROVER_GITHUB_TOKEN"},
			Vault:  &VaultConfig{Address: "https://vault.example", TokenEnv: "PATCHROVER_VAULT_TOKEN"},
		},
	}
}

func writeJSONResponse(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Fatal(err)
	}
}
