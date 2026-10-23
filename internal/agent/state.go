package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/shubham23596/patchrover/internal/model"
)

const StateVersion = "patchrover.dev/agent-state/v1alpha1"

const (
	ActionGitHubPullRequest     = "github_pull_request"
	ActionVaultDatabaseRotation = "vault_database_rotation"
)

type State struct {
	APIVersion string         `json:"apiVersion"`
	UpdatedAt  string         `json:"updatedAt"`
	Advisories []Advisory     `json:"advisories,omitempty"`
	Targets    []TargetResult `json:"targets,omitempty"`
	Actions    []Action       `json:"actions,omitempty"`
	Audit      []AuditEntry   `json:"audit"`
}

type Advisory struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity,omitempty"`
	PublishedAt string `json:"publishedAt,omitempty"`
	Source      string `json:"source"`
	URL         string `json:"url,omitempty"`
}

type TargetResult struct {
	ID        string        `json:"id"`
	CheckedAt string        `json:"checkedAt"`
	Verdict   model.Verdict `json:"verdict"`
	TrailID   string        `json:"trailId,omitempty"`
	Summary   string        `json:"summary"`
}

type Action struct {
	ID                   string                    `json:"id"`
	Type                 string                    `json:"type"`
	TargetID             string                    `json:"targetId"`
	PackID               string                    `json:"packId"`
	TrailID              string                    `json:"trailId,omitempty"`
	Status               string                    `json:"status"`
	CreatedAt            string                    `json:"createdAt"`
	UpdatedAt            string                    `json:"updatedAt"`
	Repository           string                    `json:"repository,omitempty"`
	BaseBranch           string                    `json:"baseBranch,omitempty"`
	Changes              []model.RemediationChange `json:"changes,omitempty"`
	VaultDatabase        string                    `json:"vaultDatabase,omitempty"`
	ResultURL            string                    `json:"resultUrl,omitempty"`
	ControlPlaneActionID string                    `json:"controlPlaneActionId,omitempty"`
	Error                string                    `json:"error,omitempty"`
}

type AuditEntry struct {
	Sequence  int    `json:"sequence"`
	Timestamp string `json:"timestamp"`
	Event     string `json:"event"`
	ActionID  string `json:"actionId,omitempty"`
	Detail    string `json:"detail"`
	Previous  string `json:"previousHash,omitempty"`
	Hash      string `json:"hash"`
}

func NewState() State {
	return State{APIVersion: StateVersion, Audit: []AuditEntry{}}
}

func LoadState(path string) (State, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return NewState(), nil
	}
	if err != nil {
		return State{}, fmt.Errorf("read agent state: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state State
	if err := decoder.Decode(&state); err != nil {
		return State{}, fmt.Errorf("decode agent state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return State{}, errors.New("agent state contains trailing JSON values")
	}
	if state.APIVersion != StateVersion {
		return State{}, errors.New("unsupported or missing agent state version")
	}
	if err := state.VerifyAudit(); err != nil {
		return State{}, err
	}
	return state, nil
}

func SaveState(path string, state State) error {
	if err := state.VerifyAudit(); err != nil {
		return err
	}
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return errors.New("agent state path must be a regular file, not a symlink")
	}
	temporary, err := os.CreateTemp(parent, ".patchrover-state-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}

func (state *State) AppendAudit(event, actionID, detail string) {
	if len(state.Audit) >= 1000 {
		state.Audit = append([]AuditEntry(nil), state.Audit[len(state.Audit)-999:]...)
		for index := range state.Audit {
			state.Audit[index].Sequence = index + 1
			state.Audit[index].Previous = ""
			if index > 0 {
				state.Audit[index].Previous = state.Audit[index-1].Hash
			}
			state.Audit[index].Hash = auditHash(state.Audit[index])
		}
	}
	previous := ""
	if len(state.Audit) > 0 {
		previous = state.Audit[len(state.Audit)-1].Hash
	}
	entry := AuditEntry{Sequence: len(state.Audit) + 1, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Event: event, ActionID: actionID, Detail: detail, Previous: previous}
	entry.Hash = auditHash(entry)
	state.Audit = append(state.Audit, entry)
}

func (state State) VerifyAudit() error {
	previous := ""
	for index, entry := range state.Audit {
		if entry.Sequence != index+1 || entry.Previous != previous || entry.Hash != auditHash(entry) {
			return fmt.Errorf("agent audit chain failed at entry %d", index+1)
		}
		previous = entry.Hash
	}
	return nil
}

func auditHash(entry AuditEntry) string {
	entry.Hash = ""
	data, _ := json.Marshal(entry)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func actionID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:16])
}

func (state *State) addAction(action Action) bool {
	for _, existing := range state.Actions {
		if existing.ID == action.ID {
			return false
		}
	}
	state.Actions = append(state.Actions, action)
	sort.Slice(state.Actions, func(i, j int) bool { return state.Actions[i].ID < state.Actions[j].ID })
	state.AppendAudit("action_created", action.ID, action.Type+" for "+action.TargetID)
	return true
}
