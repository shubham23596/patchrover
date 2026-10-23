package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type VaultClient struct {
	Address   string
	Token     string
	Namespace string
	HTTP      *http.Client
	AllowHTTP bool
}

func (client VaultClient) RotateDatabaseRoot(ctx context.Context, name string) error {
	if client.Token == "" {
		return errors.New("Vault token is missing")
	}
	if !resourcePattern.MatchString(name) {
		return errors.New("invalid Vault database resource name")
	}
	base, err := url.Parse(strings.TrimRight(client.Address, "/"))
	if err != nil || base.Host == "" || (!client.AllowHTTP && base.Scheme != "https") || (client.AllowHTTP && base.Scheme != "http" && base.Scheme != "https") {
		return errors.New("invalid Vault address")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/v1/database/rotate-root/" + url.PathEscape(name)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), strings.NewReader("{}"))
	if err != nil {
		return err
	}
	request.Header.Set("X-Vault-Token", client.Token)
	request.Header.Set("Content-Type", "application/json")
	if client.Namespace != "" {
		request.Header.Set("X-Vault-Namespace", client.Namespace)
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
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("Vault returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil
}
