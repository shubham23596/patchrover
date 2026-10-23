package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/shubham23596/patchrover/internal/model"
)

const maxResponseBytes = 1 << 20

type Config struct {
	Provider  string
	Endpoint  string
	Model     string
	APIKeyEnv string
}

func Explain(ctx context.Context, config Config, proposal model.RemediationProposal) (string, error) {
	switch config.Provider {
	case "", "none":
		return "", nil
	case "ollama":
		return explainOllama(ctx, config, prompt(proposal))
	case "openai-compatible":
		return explainOpenAICompatible(ctx, config, prompt(proposal))
	default:
		return "", fmt.Errorf("unsupported AI provider %q", config.Provider)
	}
}

func explainOllama(ctx context.Context, config Config, input string) (string, error) {
	if strings.TrimSpace(config.Model) == "" {
		return "", errors.New("--ai-model is required for Ollama; PatchRover never downloads a model")
	}
	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = "http://127.0.0.1:11434/api/generate"
	}
	parsed, err := validateEndpoint(endpoint)
	if err != nil {
		return "", err
	}
	host := parsed.Hostname()
	if host != "localhost" {
		address := net.ParseIP(host)
		if address == nil || !address.IsLoopback() {
			return "", errors.New("Ollama endpoint must be loopback-only; use openai-compatible for an explicit remote BYOK endpoint")
		}
	}
	requestBody := map[string]any{"model": config.Model, "prompt": input, "stream": false}
	var response struct {
		Response string `json:"response"`
	}
	if err := postJSON(ctx, endpoint, "", requestBody, &response); err != nil {
		return "", err
	}
	if strings.TrimSpace(response.Response) == "" {
		return "", errors.New("Ollama returned an empty explanation")
	}
	return strings.TrimSpace(response.Response), nil
}

func explainOpenAICompatible(ctx context.Context, config Config, input string) (string, error) {
	if strings.TrimSpace(config.Endpoint) == "" || strings.TrimSpace(config.Model) == "" || strings.TrimSpace(config.APIKeyEnv) == "" {
		return "", errors.New("openai-compatible requires --ai-endpoint, --ai-model, and --ai-key-env")
	}
	parsed, err := validateEndpoint(config.Endpoint)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" {
		return "", errors.New("remote openai-compatible endpoint must use HTTPS")
	}
	key := os.Getenv(config.APIKeyEnv)
	if key == "" {
		return "", fmt.Errorf("AI key environment variable %q is empty", config.APIKeyEnv)
	}
	requestBody := map[string]any{
		"model": config.Model,
		"messages": []map[string]string{
			{"role": "system", "content": "Explain the supplied deterministic incident-response proposal. Do not change its verdict, invent evidence, claim broader safety, or recommend autonomous production changes."},
			{"role": "user", "content": input},
		},
	}
	var response struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := postJSON(ctx, config.Endpoint, key, requestBody, &response); err != nil {
		return "", err
	}
	if len(response.Choices) == 0 || strings.TrimSpace(response.Choices[0].Message.Content) == "" {
		return "", errors.New("openai-compatible endpoint returned no explanation")
	}
	return strings.TrimSpace(response.Choices[0].Message.Content), nil
}

func validateEndpoint(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("AI endpoint must be an absolute URL without credentials, query, or fragment")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("AI endpoint must use HTTP or HTTPS")
	}
	return parsed, nil
}

func postJSON(ctx context.Context, endpoint, key string, requestBody any, responseBody any) error {
	data, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if key != "" {
		request.Header.Set("Authorization", "Bearer "+key)
	}
	client := &http.Client{
		Timeout: 45 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("AI endpoint redirects are disabled")
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("AI explanation request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("AI explanation endpoint returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes))
	if err := decoder.Decode(responseBody); err != nil {
		return fmt.Errorf("decode AI explanation response: %w", err)
	}
	return nil
}

func prompt(proposal model.RemediationProposal) string {
	redacted := struct {
		Summary            string                    `json:"summary"`
		Changes            []model.RemediationChange `json:"changes"`
		Steps              []string                  `json:"steps"`
		Tests              []string                  `json:"tests"`
		OperationalChecks  []string                  `json:"operationalChecks"`
		RequiredApprovals  []string                  `json:"requiredApprovals"`
		CredentialRotation []string                  `json:"credentialRotation,omitempty"`
		Warnings           []string                  `json:"warnings"`
	}{
		proposal.Summary,
		proposal.Changes,
		proposal.Steps,
		proposal.Tests,
		proposal.OperationalChecks,
		proposal.RequiredApprovals,
		proposal.CredentialRotation,
		proposal.Warnings,
	}
	data, _ := json.Marshal(redacted)
	return "The following data was produced by PatchRover's deterministic engine. Explain it for a human reviewer without adding facts:\n" + string(data)
}
