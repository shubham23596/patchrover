package agent

import (
	"context"
	"fmt"
	"io"
	"net/http"
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
	SourcesChecked   int
	SourceErrors     int
	TargetsChecked   int
	ActionsCreated   int
	ActionsSubmitted int
	SubmissionErrors int
}

type Runner struct {
	FeedClient       FeedClient
	ControlPlaneHTTP *http.Client
	Output           io.Writer
}

func (runner Runner) Run(ctx context.Context, config Config, once bool) error {
	for {
		report, err := runner.RunOnce(ctx, config)
		if err != nil {
			return err
		}
		if runner.Output != nil {
			fmt.Fprintf(runner.Output, "AGENT sources=%d source_errors=%d targets=%d actions_created=%d actions_submitted=%d submission_errors=%d\n", report.SourcesChecked, report.SourceErrors, report.TargetsChecked, report.ActionsCreated, report.ActionsSubmitted, report.SubmissionErrors)
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
	runAt := time.Now().UTC().Format(time.RFC3339)
	advisories := map[string]Advisory{}
	for _, existing := range state.Advisories {
		advisories[existing.Source+"\x00"+existing.ID] = existing
	}
	sourceStatuses := map[string]SourceStatus{}
	for _, existing := range state.Sources {
		sourceStatuses[existing.ID] = existing
	}
	for _, source := range config.Sources {
		report.SourcesChecked++
		status := sourceStatuses[source.ID]
		status.ID = source.ID
		status.LastAttemptAt = runAt
		items, fetchErr := runner.FeedClient.Fetch(ctx, source)
		if fetchErr != nil {
			report.SourceErrors++
			status.LastError = safeError(fetchErr)
			sourceStatuses[source.ID] = status
			state.AppendAudit("source_error", "", source.ID+": "+status.LastError)
			continue
		}
		status.LastSuccessAt = runAt
		status.AdvisoryCount = len(items)
		status.LastError = ""
		sourceStatuses[source.ID] = status
		for _, item := range items {
			key := item.Source + "\x00" + item.ID
			if existing, exists := advisories[key]; exists && existing.ObservedAt != "" {
				item.ObservedAt = existing.ObservedAt
			} else {
				item.ObservedAt = runAt
			}
			advisories[key] = item
		}
	}
	state.Sources = state.Sources[:0]
	for _, source := range config.Sources {
		state.Sources = append(state.Sources, sourceStatuses[source.ID])
	}
	sort.Slice(state.Sources, func(i, j int) bool { return state.Sources[i].ID < state.Sources[j].ID })
	allAdvisories := make([]Advisory, 0, len(advisories))
	for _, item := range advisories {
		allAdvisories = append(allAdvisories, item)
	}
	state.Advisories = retainNewestAdvisories(allAdvisories, 5000)
	if len(allAdvisories) > len(state.Advisories) {
		state.AppendAudit("advisory_limit", "", fmt.Sprintf("retained the %d newest advisories", len(state.Advisories)))
	}
	if len(state.Actions) > maxStateActions {
		return report, fmt.Errorf("agent action state exceeds the hard limit of %d", maxStateActions)
	}
	results := make([]TargetResult, 0, len(config.Targets))
	var candidateActions []Action
	for _, target := range config.Targets {
		report.TargetsChecked++
		result, actions, assessErr := assessTarget(ctx, target, config.Mode)
		if assessErr != nil {
			result = TargetResult{ID: target.ID, CheckedAt: time.Now().UTC().Format(time.RFC3339), Verdict: model.VerdictUnknown, Summary: safeError(assessErr)}
			state.AppendAudit("target_error", "", target.ID+": "+safeError(assessErr))
		} else {
			state.AppendAudit("target_assessed", "", target.ID+": "+string(result.Verdict))
		}
		results = append(results, result)
		if config.Integrations.ControlPlane != nil {
			actions = splitCommercialActions(actions)
		}
		candidateActions = append(candidateActions, actions...)
	}
	currentObservations := map[string]bool{}
	for _, action := range candidateActions {
		if action.Status == "observed" {
			currentObservations[action.ID] = true
		}
	}
	if removed := state.pruneStaleObservedActions(currentObservations); removed > 0 {
		state.AppendAudit("observations_refreshed", "", fmt.Sprintf("removed %d stale read-only observations after reassessment", removed))
	}
	for _, action := range candidateActions {
		if report.ActionsCreated >= config.Policy.MaxActionsPerRun {
			state.AppendAudit("action_limit", "", fmt.Sprintf("deferred actions after reaching per-run limit %d", config.Policy.MaxActionsPerRun))
			break
		}
		if config.Integrations.ControlPlane != nil && action.Status == "pending" {
			action.Status = "submission_pending"
		}
		added, addErr := state.addAction(action)
		if addErr != nil {
			return report, addErr
		}
		if added {
			report.ActionsCreated++
		}
	}
	state.Targets = results
	if controlPlane := config.Integrations.ControlPlane; controlPlane != nil {
		token := os.Getenv(controlPlane.TokenEnv)
		client := ControlPlaneClient{BaseURL: controlPlane.URL, Token: token, HTTP: runner.ControlPlaneHTTP}
		submissionAttempts := 0
		for index := range state.Actions {
			action := &state.Actions[index]
			if action.Status != "submission_pending" {
				continue
			}
			if submissionAttempts >= config.Policy.MaxActionsPerRun {
				state.AppendAudit("action_submission_limit", "", fmt.Sprintf("deferred submissions after reaching per-run limit %d", config.Policy.MaxActionsPerRun))
				break
			}
			submissionAttempts++
			remote, submitErr := client.Submit(ctx, *action)
			if submitErr != nil {
				report.SubmissionErrors++
				action.Error = safeError(submitErr)
				action.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
				state.AppendAudit("action_submission_failed", action.ID, action.Error)
				continue
			}
			report.ActionsSubmitted++
			action.Status = "submitted"
			action.ControlPlaneActionID = remote.ID
			action.Error = ""
			action.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			state.AppendAudit("action_submitted", action.ID, "commercial approval action "+remote.ID)
		}
	}
	state.AppendAudit("run_completed", "", fmt.Sprintf("targets=%d created=%d submitted=%d submission_errors=%d", report.TargetsChecked, report.ActionsCreated, report.ActionsSubmitted, report.SubmissionErrors))
	if err := SaveState(config.StatePath, state); err != nil {
		return report, err
	}
	return report, nil
}

func retainNewestAdvisories(input []Advisory, limit int) []Advisory {
	if limit <= 0 {
		return nil
	}
	output := append([]Advisory(nil), input...)
	sort.Slice(output, func(i, j int) bool {
		left := advisoryTime(output[i])
		right := advisoryTime(output[j])
		if !left.Equal(right) {
			return left.After(right)
		}
		if output[i].Source != output[j].Source {
			return output[i].Source < output[j].Source
		}
		return output[i].ID < output[j].ID
	})
	if len(output) > limit {
		output = output[:limit]
	}
	return output
}

func advisoryTime(item Advisory) time.Time {
	for _, value := range []string{item.PublishedAt, item.ObservedAt} {
		for _, layout := range []string{time.RFC3339, time.RFC1123, time.RFC1123Z, time.RFC822, time.RFC822Z, "2006-01-02"} {
			if parsed, err := time.Parse(layout, value); err == nil {
				return parsed
			}
		}
	}
	return time.Time{}
}

func splitCommercialActions(actions []Action) []Action {
	var output []Action
	for _, action := range actions {
		if action.Type != ActionGitHubPullRequest || len(action.Changes) <= 1 {
			output = append(output, action)
			continue
		}
		for _, change := range action.Changes {
			bounded := action
			bounded.ID = actionID(action.ID, change.Path, change.BeforeSHA256, change.OldVersion, change.NewVersion)
			bounded.Changes = []model.RemediationChange{change}
			output = append(output, bounded)
		}
	}
	return output
}

func assessTarget(ctx context.Context, target Target, mode string) (TargetResult, []Action, error) {
	responsePack, validation, err := pack.LoadFile(target.Pack)
	if err != nil {
		return TargetResult{}, nil, err
	}
	if err := pack.RequireTrusted(validation); err != nil {
		return TargetResult{}, nil, err
	}
	evidence, err := collect.AllContext(ctx, target.Evidence)
	if err != nil {
		return TargetResult{}, nil, err
	}
	trail, err := engine.Assess(responsePack, evidence)
	if err != nil {
		return TargetResult{}, nil, err
	}
	result := TargetResult{ID: target.ID, CheckedAt: time.Now().UTC().Format(time.RFC3339), Verdict: trail.Verdict, Drift: trail.Drift, TrailID: trail.ID, Summary: trail.Summary}
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
		actions = append(actions, Action{ID: id, Type: ActionGitHubPullRequest, TargetID: target.ID, PackID: responsePack.Metadata.ID, TrailID: trail.ID, Status: status, CreatedAt: now, UpdatedAt: now, Repository: target.GitHubRepository, BaseBranch: target.BaseBranch, Changes: changes})
	}
	if len(responsePack.Spec.Remediation.CredentialRotation) > 0 {
		for _, database := range target.VaultDatabaseRotations {
			id := actionID(ActionVaultDatabaseRotation, target.ID, validation.PackDigest, database)
			actions = append(actions, Action{ID: id, Type: ActionVaultDatabaseRotation, TargetID: target.ID, PackID: responsePack.Metadata.ID, TrailID: trail.ID, Status: status, CreatedAt: now, UpdatedAt: now, VaultDatabase: database})
		}
	}
	return result, actions, nil
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
