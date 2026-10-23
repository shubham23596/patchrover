package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const maxFeedBytes = 8 << 20

type FeedClient struct {
	HTTP *http.Client
}

func (client FeedClient) Fetch(ctx context.Context, source Source) ([]Advisory, error) {
	httpClient := restrictedFeedHTTPClient(client.HTTP, source.URL)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "PatchRover/0.2 (+https://github.com/shubham23596/patchrover)")
	request.Header.Set("Accept", "application/json, application/xml, application/rss+xml")
	if source.TokenEnv != "" {
		token := os.Getenv(source.TokenEnv)
		if token == "" {
			return nil, fmt.Errorf("source %s requires environment variable %s", source.ID, source.TokenEnv)
		}
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fmt.Errorf("source %s returned HTTP %d", source.ID, response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxFeedBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFeedBytes {
		return nil, errors.New("advisory feed exceeds the 8 MiB safety limit")
	}
	switch source.Kind {
	case "cisa-kev":
		return parseCISA(data, source)
	case "github-advisories":
		return parseGitHubAdvisories(data, source)
	case "rss":
		return parseRSS(data, source)
	default:
		return nil, fmt.Errorf("unsupported source kind %q", source.Kind)
	}
}

func restrictedFeedHTTPClient(original *http.Client, sourceURL string) *http.Client {
	copy := http.Client{Timeout: 20 * time.Second}
	if original != nil {
		copy = *original
		if copy.Timeout == 0 {
			copy.Timeout = 20 * time.Second
		}
	}
	initial, _ := url.Parse(sourceURL)
	copy.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 || request.URL.Scheme != "https" || !strings.EqualFold(request.URL.Hostname(), initial.Hostname()) {
			return errors.New("advisory redirect left the allowlisted HTTPS host")
		}
		return nil
	}
	return &copy
}

func parseCISA(data []byte, source Source) ([]Advisory, error) {
	var document struct {
		Vulnerabilities []struct {
			CVE              string `json:"cveID"`
			Name             string `json:"vulnerabilityName"`
			DateAdded        string `json:"dateAdded"`
			ShortDescription string `json:"shortDescription"`
		} `json:"vulnerabilities"`
	}
	if err := decodeStrictJSON(data, &document); err != nil {
		return nil, err
	}
	items := make([]Advisory, 0, len(document.Vulnerabilities))
	for _, item := range document.Vulnerabilities {
		if strings.TrimSpace(item.CVE) == "" {
			continue
		}
		title := strings.TrimSpace(item.Name)
		if title == "" {
			title = strings.TrimSpace(item.ShortDescription)
		}
		items = append(items, Advisory{ID: item.CVE, Title: title, Severity: "known-exploited", PublishedAt: item.DateAdded, Source: source.ID, URL: source.URL})
	}
	return items, nil
}

func parseGitHubAdvisories(data []byte, source Source) ([]Advisory, error) {
	var document []struct {
		GHSA      string `json:"ghsa_id"`
		CVE       string `json:"cve_id"`
		Summary   string `json:"summary"`
		Severity  string `json:"severity"`
		Published string `json:"published_at"`
		URL       string `json:"html_url"`
	}
	if err := decodeStrictJSON(data, &document); err != nil {
		return nil, err
	}
	items := make([]Advisory, 0, len(document))
	for _, item := range document {
		id := item.CVE
		if id == "" {
			id = item.GHSA
		}
		if id == "" {
			continue
		}
		items = append(items, Advisory{ID: id, Title: strings.TrimSpace(item.Summary), Severity: item.Severity, PublishedAt: item.Published, Source: source.ID, URL: item.URL})
	}
	return items, nil
}

type rssDocument struct {
	Channel struct {
		Items []struct {
			Title   string `xml:"title"`
			Link    string `xml:"link"`
			GUID    string `xml:"guid"`
			PubDate string `xml:"pubDate"`
		} `xml:"item"`
	} `xml:"channel"`
	Entries []struct {
		Title   string `xml:"title"`
		ID      string `xml:"id"`
		Updated string `xml:"updated"`
		Link    struct {
			Href string `xml:"href,attr"`
		} `xml:"link"`
	} `xml:"entry"`
}

func parseRSS(data []byte, source Source) ([]Advisory, error) {
	var document rssDocument
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode RSS/Atom feed: %w", err)
	}
	var items []Advisory
	for _, item := range document.Channel.Items {
		id := strings.TrimSpace(item.GUID)
		if id == "" {
			id = strings.TrimSpace(item.Link)
		}
		if id != "" && strings.TrimSpace(item.Title) != "" {
			items = append(items, Advisory{ID: id, Title: strings.TrimSpace(item.Title), PublishedAt: item.PubDate, Source: source.ID, URL: strings.TrimSpace(item.Link)})
		}
	}
	for _, item := range document.Entries {
		if strings.TrimSpace(item.ID) != "" && strings.TrimSpace(item.Title) != "" {
			items = append(items, Advisory{ID: strings.TrimSpace(item.ID), Title: strings.TrimSpace(item.Title), PublishedAt: item.Updated, Source: source.ID, URL: strings.TrimSpace(item.Link.Href)})
		}
	}
	return items, nil
}

func decodeStrictJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("advisory feed contains trailing JSON values")
	}
	return nil
}
