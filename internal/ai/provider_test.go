package ai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shubham23596/patchrover/internal/model"
)

func TestOllamaExplanationRequiresLoopbackAndNeverDownloads(t *testing.T) {
	_, err := Explain(context.Background(), Config{Provider: "ollama", Endpoint: "https://models.example.invalid/api/generate", Model: "local"}, model.RemediationProposal{})
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected loopback-only error, got %v", err)
	}
	_, err = Explain(context.Background(), Config{Provider: "ollama"}, model.RemediationProposal{})
	if err == nil || !strings.Contains(err.Error(), "never downloads") {
		t.Fatalf("expected explicit model error, got %v", err)
	}
}

func TestOllamaExplanationUsesExplicitLocalEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Fatalf("unexpected method %s", request.Method)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"response":"Review the deterministic evidence and approvals."}`))
	}))
	defer server.Close()

	explanation, err := Explain(context.Background(), Config{Provider: "ollama", Endpoint: server.URL, Model: "already-installed"}, model.RemediationProposal{Summary: "Synthetic proposal"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(explanation, "deterministic evidence") {
		t.Fatalf("unexpected explanation %q", explanation)
	}
}

func TestRemoteProviderRequiresHTTPSAndExplicitKeyEnvironment(t *testing.T) {
	_, err := Explain(context.Background(), Config{Provider: "openai-compatible", Endpoint: "http://example.invalid/v1/chat/completions", Model: "model", APIKeyEnv: "TEST_KEY"}, model.RemediationProposal{})
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected HTTPS error, got %v", err)
	}
}
