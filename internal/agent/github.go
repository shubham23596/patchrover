package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shubham23596/patchrover/internal/proposal"
)

type GitHubClient struct {
	BaseURL   string
	Token     string
	HTTP      *http.Client
	AllowHTTP bool
}

func (client GitHubClient) OpenRemediationPullRequest(ctx context.Context, action Action) (string, error) {
	if client.Token == "" {
		return "", errors.New("GitHub token is missing")
	}
	if !repositoryPattern.MatchString(action.Repository) || len(action.Changes) == 0 {
		return "", errors.New("GitHub action has an invalid repository or no bounded changes")
	}
	if len(action.ID) < 8 {
		return "", errors.New("GitHub action ID is invalid")
	}
	base := action.BaseBranch
	if base == "" {
		base = "main"
	}
	parts := strings.Split(action.Repository, "/")
	repoPath := "/repos/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1])
	var reference struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := client.request(ctx, http.MethodGet, repoPath+"/git/ref/heads/"+url.PathEscape(base), nil, &reference); err != nil {
		return "", fmt.Errorf("read base branch: %w", err)
	}
	if reference.Object.SHA == "" {
		return "", errors.New("GitHub base branch has no commit SHA")
	}
	type preparedFile struct {
		path, sha, content string
	}
	prepared := make([]preparedFile, 0, len(action.Changes))
	for _, change := range action.Changes {
		if strings.HasPrefix(change.Path, "/") || strings.Contains(change.Path, "..") || strings.ContainsAny(change.Path, "\r\n\x00") {
			return "", fmt.Errorf("unsafe repository path %q", change.Path)
		}
		var file struct {
			SHA      string `json:"sha"`
			Content  string `json:"content"`
			Encoding string `json:"encoding"`
		}
		endpoint := repoPath + "/contents/" + escapePath(change.Path) + "?ref=" + url.QueryEscape(base)
		if err := client.request(ctx, http.MethodGet, endpoint, nil, &file); err != nil {
			return "", fmt.Errorf("read %s: %w", change.Path, err)
		}
		if file.Encoding != "base64" || file.SHA == "" {
			return "", fmt.Errorf("GitHub returned unsupported content for %s", change.Path)
		}
		current, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(file.Content, "\n", ""))
		if err != nil {
			return "", fmt.Errorf("decode %s: %w", change.Path, err)
		}
		updated, err := proposal.ApplyChange(current, change)
		if err != nil {
			return "", err
		}
		prepared = append(prepared, preparedFile{path: change.Path, sha: file.SHA, content: base64.StdEncoding.EncodeToString(updated)})
	}
	branch := "patchrover/" + safeBranch(action.PackID) + "-" + action.ID[:8]
	err := client.request(ctx, http.MethodPost, repoPath+"/git/refs", map[string]string{"ref": "refs/heads/" + branch, "sha": reference.Object.SHA}, nil)
	if err != nil && !strings.Contains(err.Error(), "HTTP 422") {
		return "", fmt.Errorf("create remediation branch: %w", err)
	}
	for _, file := range prepared {
		payload := map[string]string{
			"message": "fix: remediate " + action.PackID,
			"content": file.content,
			"sha":     file.sha,
			"branch":  branch,
		}
		if err := client.request(ctx, http.MethodPut, repoPath+"/contents/"+escapePath(file.path), payload, nil); err != nil {
			return "", fmt.Errorf("update %s: %w", file.path, err)
		}
	}
	var pullRequest struct {
		HTMLURL string `json:"html_url"`
	}
	payload := map[string]string{
		"title": "PatchRover: remediate " + action.PackID,
		"head":  branch,
		"base":  base,
		"body":  "PatchRover created this bounded dependency remediation from deterministic signed-pack evidence. Review tests and deployment separately; no production deployment was performed.",
	}
	if err := client.request(ctx, http.MethodPost, repoPath+"/pulls", payload, &pullRequest); err != nil {
		return "", fmt.Errorf("create pull request: %w", err)
	}
	return pullRequest.HTMLURL, nil
}

func (client GitHubClient) request(ctx context.Context, method, endpoint string, payload, result any) error {
	base, err := url.Parse(strings.TrimRight(client.BaseURL, "/"))
	if err != nil || base.Host == "" || (!client.AllowHTTP && base.Scheme != "https") || (client.AllowHTTP && base.Scheme != "http" && base.Scheme != "https") {
		return errors.New("invalid GitHub API base URL")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	base.Path = strings.TrimRight(base.Path, "/") + parsed.Path
	base.RawQuery = parsed.RawQuery
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, base.String(), body)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+client.Token)
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", "PatchRover/0.2")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	httpClient := client.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second}
	}
	copy := *httpClient
	copy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	response, err := copy.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(data)))
	}
	if result != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, result); err != nil {
			return err
		}
	}
	return nil
}

func escapePath(path string) string {
	parts := strings.Split(path, "/")
	for index := range parts {
		parts[index] = url.PathEscape(parts[index])
	}
	return strings.Join(parts, "/")
}

func safeBranch(value string) string {
	var builder strings.Builder
	for _, character := range strings.ToLower(value) {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
			builder.WriteRune(character)
		} else {
			builder.WriteByte('-')
		}
	}
	return strings.Trim(builder.String(), "-")
}
