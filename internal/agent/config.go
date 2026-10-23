package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/shubham23596/patchrover/internal/collect"
)

const ConfigVersion = "patchrover.dev/agent/v1alpha1"

var (
	targetIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	repositoryPattern  = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	resourcePattern    = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	environmentPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

type Config struct {
	APIVersion   string       `json:"apiVersion"`
	Mode         string       `json:"mode"`
	Interval     string       `json:"interval"`
	StatePath    string       `json:"statePath"`
	AllowedHosts []string     `json:"allowedHosts"`
	Sources      []Source     `json:"sources,omitempty"`
	Targets      []Target     `json:"targets"`
	Policy       Policy       `json:"policy"`
	Integrations Integrations `json:"integrations,omitempty"`
	configPath   string
}

type Source struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	URL      string `json:"url"`
	TokenEnv string `json:"tokenEnv,omitempty"`
}

type Target struct {
	ID                     string          `json:"id"`
	Pack                   string          `json:"pack"`
	Evidence               collect.Options `json:"evidence"`
	GitHubRepository       string          `json:"githubRepository,omitempty"`
	BaseBranch             string          `json:"baseBranch,omitempty"`
	VaultDatabaseRotations []string        `json:"vaultDatabaseRotations,omitempty"`
}

type Policy struct {
	MaxActionsPerRun int `json:"maxActionsPerRun"`
}

type Integrations struct {
	GitHub *GitHubConfig `json:"github,omitempty"`
	Vault  *VaultConfig  `json:"vault,omitempty"`
}

type GitHubConfig struct {
	APIBase  string `json:"apiBase"`
	TokenEnv string `json:"tokenEnv"`
}

type VaultConfig struct {
	Address   string `json:"address"`
	TokenEnv  string `json:"tokenEnv"`
	Namespace string `json:"namespace,omitempty"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read agent config: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode agent config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("agent config contains trailing JSON values")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return Config{}, err
	}
	config.configPath = absolute
	config.resolvePaths(filepath.Dir(absolute))
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (config *Config) resolvePaths(base string) {
	resolve := func(value string) string {
		if value == "" || filepath.IsAbs(value) {
			return value
		}
		return filepath.Join(base, value)
	}
	config.StatePath = resolve(config.StatePath)
	for index := range config.Targets {
		config.Targets[index].Pack = resolve(config.Targets[index].Pack)
		evidence := &config.Targets[index].Evidence
		evidence.RepositoryPath = resolve(evidence.RepositoryPath)
		evidence.SBOMPath = resolve(evidence.SBOMPath)
		evidence.EvidencePath = resolve(evidence.EvidencePath)
		evidence.KubeSnapshot = resolve(evidence.KubeSnapshot)
	}
}

func (config Config) IntervalDuration() time.Duration {
	duration, _ := time.ParseDuration(config.Interval)
	return duration
}

func (config Config) Validate() error {
	if config.APIVersion != ConfigVersion {
		return fmt.Errorf("unsupported agent apiVersion %q", config.APIVersion)
	}
	if config.Mode != "observe" && config.Mode != "propose" {
		return errors.New("agent mode must be observe or propose")
	}
	duration, err := time.ParseDuration(config.Interval)
	if err != nil || duration < time.Minute {
		return errors.New("agent interval must be at least 1m")
	}
	if strings.TrimSpace(config.StatePath) == "" || len(config.Targets) == 0 {
		return errors.New("agent statePath and at least one target are required")
	}
	if config.Policy.MaxActionsPerRun < 1 || config.Policy.MaxActionsPerRun > 20 {
		return errors.New("maxActionsPerRun must be between 1 and 20")
	}
	allowed := map[string]bool{}
	for _, host := range config.AllowedHosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" || strings.ContainsAny(host, "/:@") {
			return fmt.Errorf("invalid allowed host %q", host)
		}
		allowed[host] = true
	}
	validateHTTPS := func(raw string) error {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
			return fmt.Errorf("endpoint must be an absolute HTTPS URL: %q", raw)
		}
		if !allowed[strings.ToLower(parsed.Hostname())] {
			return fmt.Errorf("endpoint host %q is not allowlisted", parsed.Hostname())
		}
		return nil
	}
	seenSources := map[string]bool{}
	for _, source := range config.Sources {
		if !targetIDPattern.MatchString(source.ID) || seenSources[source.ID] {
			return fmt.Errorf("invalid or duplicate source id %q", source.ID)
		}
		seenSources[source.ID] = true
		if source.Kind != "cisa-kev" && source.Kind != "github-advisories" && source.Kind != "rss" {
			return fmt.Errorf("unsupported source kind %q", source.Kind)
		}
		if source.TokenEnv != "" && !environmentPattern.MatchString(source.TokenEnv) {
			return fmt.Errorf("source %s has an invalid tokenEnv name", source.ID)
		}
		if err := validateHTTPS(source.URL); err != nil {
			return err
		}
	}
	seenTargets := map[string]bool{}
	for _, target := range config.Targets {
		if !targetIDPattern.MatchString(target.ID) || seenTargets[target.ID] {
			return fmt.Errorf("invalid or duplicate target id %q", target.ID)
		}
		seenTargets[target.ID] = true
		if target.Pack == "" {
			return fmt.Errorf("target %s requires a pack", target.ID)
		}
		if target.Evidence.RepositoryPath == "" && target.Evidence.SBOMPath == "" && target.Evidence.ImageReference == "" && target.Evidence.EvidencePath == "" && target.Evidence.KubeContext == "" && target.Evidence.KubeSnapshot == "" {
			return fmt.Errorf("target %s requires explicit evidence", target.ID)
		}
		if target.GitHubRepository != "" {
			if !repositoryPattern.MatchString(target.GitHubRepository) || config.Integrations.GitHub == nil {
				return fmt.Errorf("target %s has invalid GitHub repository or missing integration", target.ID)
			}
		}
		for _, name := range target.VaultDatabaseRotations {
			if !resourcePattern.MatchString(name) || config.Integrations.Vault == nil {
				return fmt.Errorf("target %s has invalid Vault database rotation or missing integration", target.ID)
			}
		}
	}
	if config.Integrations.GitHub != nil {
		if !environmentPattern.MatchString(config.Integrations.GitHub.TokenEnv) {
			return errors.New("GitHub integration requires a tokenEnv name")
		}
		if err := validateHTTPS(config.Integrations.GitHub.APIBase); err != nil {
			return err
		}
	}
	if config.Integrations.Vault != nil {
		if !environmentPattern.MatchString(config.Integrations.Vault.TokenEnv) {
			return errors.New("Vault integration requires a tokenEnv name")
		}
		if err := validateHTTPS(config.Integrations.Vault.Address); err != nil {
			return err
		}
	}
	return nil
}
