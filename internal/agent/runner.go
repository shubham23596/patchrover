package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/shubham23596/patchrover/internal/collect"
	"github.com/shubham23596/patchrover/internal/engine"
	"github.com/shubham23596/patchrover/internal/model"
	"github.com/shubham23596/patchrover/internal/pack"
	"github.com/shubham23596/patchrover/internal/proposal"
)

type RunReport struct {
	SourcesChecked int
	SourceErrors   int
	TargetsChecked int
	ActionsCreated int
}

type Runner struct {
	FeedClient FeedClient
	Output     io.Writer
}

func (runner Runner) Run(ctx context.Context, config Config, once bool) error {
	for {
		report, err := runner.RunOnce(ctx, config)
		if err != nil {
			return err
		}
		if runner.Output != nil {
			fmt.Fprintf(runner.Output, "AGENT sources=%d source_errors=%d targets=%d actions_created=%d\n", report.SourcesChecked, report.SourceErrors, report.TargetsChecked, report.ActionsCreated)
		}
		if once {
			return nil
		}
		timer := time.NewTimer(config.IntervalDuration())
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func (runner Runner) RunOnce(ctx context.Context, config Config) (RunReport, error) {
	if err := config.Validate(); err != nil {
		return RunReport{}, err
	}
	state, err := LoadState(config.StatePath)
	if err != nil {
		return RunReport{}, err
	}
	report := RunReport{}
	advisories := map[string]Advisory{}
	for _, existing := range state.Advisories {
		advisories[existing.Source+"\x00"+existing.ID] = existing
	}
	for _, source := range config.Sources {
		report.SourcesChecked++
		items, fetchErr := runner.FeedClient.Fetch(ctx, source)
		if fetchErr != nil {
			report.SourceErrors++
			state.AppendAudit("source_error", "", source.ID+": "+safeError(fetchErr))
			continue
		}
		for _, item := range items {
			advisories[item.Source+"\x00"+item.ID] = item
		}
	}
	state.Advisories = state.Advisories[:0]
	for _, item := range advisories {
		state.Advisories = append(state.Advisories, item)
	}
	sort.Slice(state.Advisories, func(i, j int) bool {
		if state.Advisories[i].Source == state.Advisories[j].Source {
			return state.Advisories[i].ID < state.Advisories[j].ID
		}
		return state.Advisories[i].Source < state.Advisories[j].Source
	})
	if len(state.Advisories) > 5000 {
		state.Advisories = append([]Advisory(nil), state.Advisories[:5000]...)
		state.AppendAudit("advisory_limit", "", "retained first 5000 source and advisory IDs")
	}
	results := make([]TargetResult, 0, len(config.Targets))
	for _, target := range config.Targets {
		report.TargetsChecked++
		result, actions, assessErr := assessTarget(target, config.Mode)
		if assessErr != nil {
			result = TargetResult{ID: target.ID, CheckedAt: time.Now().UTC().Format(time.RFC3339), Verdict: model.VerdictUnknown, Summary: safeError(assessErr)}
			state.AppendAudit("target_error", "", target.ID+": "+safeError(assessErr))
		} else {
			state.AppendAudit("target_assessed", "", target.ID+": "+string(result.Verdict))
		}
		results = append(results, result)
		for _, action := range actions {
			if report.ActionsCreated >= config.Policy.MaxActionsPerRun {
				state.AppendAudit("action_limit", "", fmt.Sprintf("deferred actions after reaching per-run limit %d", config.Policy.MaxActionsPerRun))
				break
			}
			if state.addAction(action) {
				report.ActionsCreated++
			}
		}
	}
	state.Targets = results
	state.AppendAudit("run_completed", "", fmt.Sprintf("targets=%d created=%d", report.TargetsChecked, report.ActionsCreated))
	if err := SaveState(config.StatePath, state); err != nil {
		return report, err
	}
	return report, nil
}

// ApplyApproved executes one exact action after a separately persisted human
// approval. The running state is saved before the external mutation so a crash
// cannot silently retry an action whose outcome may be unknown.
func ApplyApproved(ctx context.Context, config Config, id string) (string, error) {
	if err := config.Validate(); err != nil {
		return "", err
	}
	state, err := LoadState(config.StatePath)
	if err != nil {
		return "", err
	}
	index := -1
	for candidate := range state.Actions {
		if state.Actions[candidate].ID == id {
			index = candidate
			break
		}
	}
	if index < 0 {
		return "", fmt.Errorf("action %s was not found", id)
	}
	if state.Actions[index].Status != "approved" {
		return "", fmt.Errorf("action %s cannot run from status %s", id, state.Actions[index].Status)
	}
	action := state.Actions[index]
	state.Actions[index].Status = "running"
	state.Actions[index].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	state.AppendAudit("action_started", id, action.Type+" after human approval")
	if err := SaveState(config.StatePath, state); err != nil {
		return "", err
	}

	resultURL, executeErr := executeAction(ctx, config, action)
	state, loadErr := LoadState(config.StatePath)
	if loadErr != nil {
		return "", loadErr
	}
	index = -1
	for candidate := range state.Actions {
		if state.Actions[candidate].ID == id {
			index = candidate
			break
		}
	}
	if index < 0 || state.Actions[index].Status != "running" {
		return "", errors.New("approved action state changed while it was running")
	}
	state.Actions[index].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if executeErr != nil {
		state.Actions[index].Status = "failed"
		state.Actions[index].Error = safeError(executeErr)
		state.AppendAudit("action_failed", id, action.Type+": "+safeError(executeErr))
	} else {
		state.Actions[index].Status = "completed"
		state.Actions[index].ResultURL = resultURL
		state.Actions[index].Error = ""
		state.AppendAudit("action_completed", id, action.Type)
	}
	if err := SaveState(config.StatePath, state); err != nil {
		return "", err
	}
	if executeErr != nil {
		return "", executeErr
	}
	return resultURL, nil
}

func assessTarget(target Target, mode string) (TargetResult, []Action, error) {
	responsePack, validation, err := pack.LoadFile(target.Pack)
	if err != nil {
		return TargetResult{}, nil, err
	}
	if err := pack.RequireTrusted(validation); err != nil {
		return TargetResult{}, nil, err
	}
	evidence, err := collect.All(target.Evidence)
	if err != nil {
		return TargetResult{}, nil, err
	}
	trail, err := engine.Assess(responsePack, evidence)
	if err != nil {
		return TargetResult{}, nil, err
	}
	result := TargetResult{ID: target.ID, CheckedAt: time.Now().UTC().Format(time.RFC3339), Verdict: trail.Verdict, TrailID: trail.ID, Summary: trail.Summary}
	if trail.Verdict != model.VerdictAffected {
		return result, nil, nil
	}
	now := time.Now().UTC().Format(time.RFC3339)
	status := "pending"
	if mode == "observe" {
		status = "observed"
	}
	var actions []Action
	remediation := proposal.Build(responsePack, trail, target.Evidence.RepositoryPath)
	if target.GitHubRepository != "" && len(remediation.Changes) > 0 {
		changes := append([]model.RemediationChange(nil), remediation.Changes...)
		fingerprint := ""
		for index := range changes {
			fingerprint += changes[index].Path + "\x00" + changes[index].BeforeSHA256 + "\x00" + changes[index].NewVersion + "\x00"
			changes[index].Patch = ""
		}
		id := actionID(ActionGitHubPullRequest, target.ID, validation.PackDigest, target.GitHubRepository, fingerprint)
		actions = append(actions, Action{ID: id, Type: ActionGitHubPullRequest, TargetID: target.ID, PackID: responsePack.Metadata.ID, Status: status, CreatedAt: now, UpdatedAt: now, Repository: target.GitHubRepository, BaseBranch: target.BaseBranch, Changes: changes})
	}
	if len(responsePack.Spec.Remediation.CredentialRotation) > 0 {
		for _, database := range target.VaultDatabaseRotations {
			id := actionID(ActionVaultDatabaseRotation, target.ID, validation.PackDigest, database)
			actions = append(actions, Action{ID: id, Type: ActionVaultDatabaseRotation, TargetID: target.ID, PackID: responsePack.Metadata.ID, Status: status, CreatedAt: now, UpdatedAt: now, VaultDatabase: database})
		}
	}
	return result, actions, nil
}

func executeAction(ctx context.Context, config Config, action Action) (string, error) {
	switch action.Type {
	case ActionGitHubPullRequest:
		if config.Integrations.GitHub == nil {
			return "", errors.New("GitHub integration is not configured")
		}
		token := os.Getenv(config.Integrations.GitHub.TokenEnv)
		client := GitHubClient{BaseURL: config.Integrations.GitHub.APIBase, Token: token}
		return client.OpenRemediationPullRequest(ctx, action)
	case ActionVaultDatabaseRotation:
		if config.Integrations.Vault == nil {
			return "", errors.New("Vault integration is not configured")
		}
		token := os.Getenv(config.Integrations.Vault.TokenEnv)
		client := VaultClient{Address: config.Integrations.Vault.Address, Token: token, Namespace: config.Integrations.Vault.Namespace}
		return "", client.RotateDatabaseRoot(ctx, action.VaultDatabase)
	default:
		return "", fmt.Errorf("unsupported action type %q", action.Type)
	}
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.ReplaceAll(strings.ReplaceAll(err.Error(), "\n", " "), "\r", " ")
	if len(value) > 500 {
		value = value[:500]
	}
	return value
}
