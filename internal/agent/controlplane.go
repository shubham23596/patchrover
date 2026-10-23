package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ControlPlaneClient struct {
	BaseURL   string
	Token     string
	HTTP      *http.Client
	AllowHTTP bool
}

type controlPlaneSubmission struct {
	ExternalID      string          `json:"externalId"`
	Type            string          `json:"type"`
	TargetID        string          `json:"targetId"`
	PackID          string          `json:"packId"`
	Proposal        json.RawMessage `json:"proposal"`
	EvidenceSummary json.RawMessage `json:"evidenceSummary"`
}

type controlPlaneAction struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

func (client ControlPlaneClient) Submit(ctx context.Context, action Action) (controlPlaneAction, error) {
	if strings.TrimSpace(client.Token) == "" {
		return controlPlaneAction{}, errors.New("control plane token is missing")
	}
	base, err := url.Parse(strings.TrimRight(client.BaseURL, "/"))
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return controlPlaneAction{}, errors.New("invalid control plane URL")
	}
	if base.Scheme != "https" && !(client.AllowHTTP && base.Scheme == "http" && (base.Hostname() == "127.0.0.1" || base.Hostname() == "localhost" || base.Hostname() == "::1")) {
		return controlPlaneAction{}, errors.New("control plane URL must use HTTPS")
	}
	proposal, err := commercialProposal(action)
	if err != nil {
		return controlPlaneAction{}, err
	}
	evidence, err := json.Marshal(map[string]string{
		"verdict": "affected", "targetId": action.TargetID, "trailId": action.TrailID,
		"collector": "patchrover-deterministic-agent",
	})
	if err != nil {
		return controlPlaneAction{}, err
	}
	payload, err := json.Marshal(controlPlaneSubmission{
		ExternalID: action.ID, Type: action.Type, TargetID: action.TargetID, PackID: action.PackID,
		Proposal: proposal, EvidenceSummary: evidence,
	})
	if err != nil {
		return controlPlaneAction{}, err
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/agent/actions"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), bytes.NewReader(payload))
	if err != nil {
		return controlPlaneAction{}, err
	}
	request.Header.Set("Authorization", "Bearer "+client.Token)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "PatchRover-Agent/0.1")
	httpClient := client.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second}
	}
	copyClient := *httpClient
	copyClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	response, err := copyClient.Do(request)
	if err != nil {
		return controlPlaneAction{}, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return controlPlaneAction{}, err
	}
	if response.StatusCode != http.StatusCreated {
		return controlPlaneAction{}, fmt.Errorf("control plane returned HTTP %d", response.StatusCode)
	}
	var remote controlPlaneAction
	if err := json.Unmarshal(data, &remote); err != nil || remote.ID == "" || remote.Status == "" {
		return controlPlaneAction{}, errors.New("control plane returned an invalid action")
	}
	return remote, nil
}

func commercialProposal(action Action) (json.RawMessage, error) {
	switch action.Type {
	case ActionGitHubPullRequest:
		if len(action.Changes) != 1 {
			return nil, errors.New("commercial control plane requires exactly one bounded repository change per action")
		}
		change := action.Changes[0]
		return json.Marshal(map[string]any{
			"repository": action.Repository, "baseBranch": action.BaseBranch,
			"filePath": change.Path, "line": change.Line, "beforeSha256": change.BeforeSHA256,
			"oldVersion": change.OldVersion, "newVersion": change.NewVersion, "package": change.Package,
		})
	case ActionVaultDatabaseRotation:
		return json.Marshal(map[string]string{"database": action.VaultDatabase})
	default:
		return nil, fmt.Errorf("unsupported commercial action type %q", action.Type)
	}
}
