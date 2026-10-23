package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/shubham23596/patchrover/internal/agent"
	"github.com/shubham23596/patchrover/internal/ai"
	"github.com/shubham23596/patchrover/internal/collect"
	"github.com/shubham23596/patchrover/internal/engine"
	"github.com/shubham23596/patchrover/internal/model"
	"github.com/shubham23596/patchrover/internal/pack"
	"github.com/shubham23596/patchrover/internal/proposal"
	"github.com/shubham23596/patchrover/internal/receipt"
)

var Version = "0.1.0"

func Run(args []string, stdout, stderr io.Writer) int {
	return RunWithInput(args, os.Stdin, stdout, stderr)
}

func RunWithInput(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printHelp(stdout)
		return 0
	}
	switch args[0] {
	case "help", "-h", "--help":
		printHelp(stdout)
		return 0
	case "version", "--version":
		fmt.Fprintln(stdout, Version)
		return 0
	case "assess":
		return runAssess(args[1:], stdout, stderr)
	case "propose":
		return runPropose(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "receipt":
		return runReceipt(args[1:], stdout, stderr)
	case "pack":
		return runPack(args[1:], stdout, stderr)
	case "agent":
		return runAgent(args[1:], stdin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		printHelp(stderr)
		return 1
	}
}

func runAgent(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: patchrover agent run|status|review")
		return 1
	}
	switch args[0] {
	case "run":
		set := flag.NewFlagSet("agent run", flag.ContinueOnError)
		set.SetOutput(stderr)
		configPath := set.String("config", "", "agent JSON configuration")
		once := set.Bool("once", false, "run one cycle and exit")
		if err := set.Parse(args[1:]); err != nil {
			return 1
		}
		if *configPath == "" {
			fmt.Fprintln(stderr, "agent run requires --config")
			return 1
		}
		config, err := agent.LoadConfig(*configPath)
		if err != nil {
			fmt.Fprintln(stderr, "load agent config:", err)
			return 1
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		if err := (agent.Runner{Output: stdout}).Run(ctx, config, *once); err != nil {
			fmt.Fprintln(stderr, "agent run failed:", err)
			return 1
		}
		return 0
	case "status":
		set := flag.NewFlagSet("agent status", flag.ContinueOnError)
		set.SetOutput(stderr)
		statePath := set.String("state", "", "agent state JSON")
		if err := set.Parse(args[1:]); err != nil || *statePath == "" {
			fmt.Fprintln(stderr, "agent status requires --state")
			return 1
		}
		state, err := agent.LoadState(*statePath)
		if err != nil {
			fmt.Fprintln(stderr, "load agent state:", err)
			return 1
		}
		fmt.Fprintf(stdout, "UPDATED %s\nADVISORIES %d\nTARGETS %d\nACTIONS %d\n", state.UpdatedAt, len(state.Advisories), len(state.Targets), len(state.Actions))
		for _, target := range state.Targets {
			fmt.Fprintf(stdout, "TARGET %s verdict=%s trail=%s\n", target.ID, target.Verdict, target.TrailID)
		}
		for _, action := range state.Actions {
			fmt.Fprintf(stdout, "ACTION %s type=%s status=%s target=%s\n", action.ID, action.Type, action.Status, action.TargetID)
			if action.Status == "pending" || action.Status == "failed" {
				fmt.Fprintf(stdout, "REVIEW patchrover agent review --config CONFIG --action %s\n", action.ID)
			}
		}
		return 0
	case "review":
		set := flag.NewFlagSet("agent review", flag.ContinueOnError)
		set.SetOutput(stderr)
		configPath := set.String("config", "", "agent JSON configuration")
		actionID := set.String("action", "", "exact pending action ID")
		if err := set.Parse(args[1:]); err != nil || *configPath == "" || *actionID == "" {
			fmt.Fprintln(stderr, "agent review requires --config and --action")
			return 1
		}
		config, err := agent.LoadConfig(*configPath)
		if err != nil {
			fmt.Fprintln(stderr, "load agent config:", err)
			return 1
		}
		state, err := agent.LoadState(config.StatePath)
		if err != nil {
			fmt.Fprintln(stderr, "load agent state:", err)
			return 1
		}
		action, ok := findAction(state.Actions, *actionID)
		if !ok {
			fmt.Fprintln(stderr, "review action: action was not found")
			return 1
		}
		if action.Status != "pending" && action.Status != "failed" {
			fmt.Fprintf(stderr, "review action: action cannot be reviewed from status %s\n", action.Status)
			return 1
		}
		printActionReview(stdout, action)
		fmt.Fprint(stdout, "Apply this exact fix? Type yes to approve: ")
		answer, readErr := bufio.NewReader(stdin).ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			fmt.Fprintln(stderr, "read approval:", readErr)
			return 1
		}
		if strings.TrimSpace(answer) != "yes" {
			fmt.Fprintln(stdout, "CANCELLED no change was approved or applied")
			return 0
		}
		if err := agent.Approve(config.StatePath, action.ID); err != nil {
			fmt.Fprintln(stderr, "approve action:", err)
			return 1
		}
		resultURL, err := agent.ApplyApproved(context.Background(), config, action.ID)
		if err != nil {
			fmt.Fprintln(stderr, "apply approved action:", err)
			return 1
		}
		fmt.Fprintln(stdout, "COMPLETED", action.ID)
		if resultURL != "" {
			fmt.Fprintln(stdout, "RESULT", resultURL)
		}
		return 0
	default:
		fmt.Fprintln(stderr, "usage: patchrover agent run|status|review")
		return 1
	}
}

func findAction(actions []agent.Action, id string) (agent.Action, bool) {
	for _, action := range actions {
		if action.ID == id {
			return action, true
		}
	}
	return agent.Action{}, false
}

func printActionReview(output io.Writer, action agent.Action) {
	fmt.Fprintf(output, "\nFIX REQUIRES APPROVAL\nACTION %s\nTYPE   %s\nTARGET %s\nPACK   %s\n", action.ID, action.Type, action.TargetID, action.PackID)
	switch action.Type {
	case agent.ActionGitHubPullRequest:
		fmt.Fprintf(output, "REPOSITORY %s\nBASE       %s\n", action.Repository, action.BaseBranch)
		for _, change := range action.Changes {
			fmt.Fprintf(output, "CHANGE     %s: %s -> %s\n", change.Path, change.OldVersion, change.NewVersion)
		}
	case agent.ActionVaultDatabaseRotation:
		fmt.Fprintf(output, "MACHINE CREDENTIAL %s\n", action.VaultDatabase)
	}
	fmt.Fprintln(output, "PatchRover will apply only this action. It will not merge or deploy the result.")
}

type evidenceFlags struct {
	repositoryPath string
	sbomPath       string
	imageReference string
	evidencePath   string
	kubeContext    string
	kubeSnapshot   string
}

func addEvidenceFlags(set *flag.FlagSet, values *evidenceFlags) {
	set.StringVar(&values.repositoryPath, "repo", "", "authorized repository directory")
	set.StringVar(&values.sbomPath, "sbom", "", "CycloneDX or SPDX JSON document")
	set.StringVar(&values.imageReference, "image", "", "OCI image reference or digest")
	set.StringVar(&values.evidencePath, "evidence", "", "explicit PatchRover evidence JSON")
	set.StringVar(&values.kubeContext, "kube-context", "", "explicit read-only kubectl context")
	set.StringVar(&values.kubeSnapshot, "kube-snapshot", "", "offline Kubernetes PodList JSON")
}

func (values evidenceFlags) options() collect.Options {
	return collect.Options{
		RepositoryPath: values.repositoryPath,
		SBOMPath:       values.sbomPath,
		ImageReference: values.imageReference,
		EvidencePath:   values.evidencePath,
		KubeContext:    values.kubeContext,
		KubeSnapshot:   values.kubeSnapshot,
	}
}

func (values evidenceFlags) empty() bool {
	return values.repositoryPath == "" && values.sbomPath == "" && values.imageReference == "" && values.evidencePath == "" && values.kubeContext == "" && values.kubeSnapshot == ""
}

func runAssess(args []string, stdout, stderr io.Writer) int {
	set := flag.NewFlagSet("assess", flag.ContinueOnError)
	set.SetOutput(stderr)
	packPath := set.String("pack", "", "signed response-pack JSON")
	outPath := set.String("out", "patchrover-trail.json", "trail output path")
	force := set.Bool("force", false, "replace an existing output file")
	var evidence evidenceFlags
	addEvidenceFlags(set, &evidence)
	if err := set.Parse(args); err != nil {
		return 1
	}
	if *packPath == "" || evidence.empty() {
		fmt.Fprintln(stderr, "assess requires --pack and at least one evidence source")
		return 1
	}
	responsePack, validation, err := pack.LoadFile(*packPath)
	if err != nil {
		fmt.Fprintln(stderr, "pack validation failed:", err)
		return 1
	}
	if err := pack.RequireTrusted(validation); err != nil {
		fmt.Fprintln(stderr, "pack trust failed:", err)
		return 1
	}
	items, err := collect.All(evidence.options())
	if err != nil {
		fmt.Fprintln(stderr, "evidence collection failed:", err)
		return 1
	}
	trail, err := engine.Assess(responsePack, items)
	if err != nil {
		fmt.Fprintln(stderr, "assessment failed:", err)
		return 1
	}
	if err := writeJSON(*outPath, trail, *force); err != nil {
		fmt.Fprintln(stderr, "write trail:", err)
		return 1
	}
	fmt.Fprintf(stdout, "VERDICT  %s\n", strings.ToUpper(string(trail.Verdict)))
	fmt.Fprintf(stdout, "PACK     %s@%s (%s)\n", trail.PackID, trail.PackVersion, validation.PackDigest)
	fmt.Fprintf(stdout, "TRAIL    %s\n", trail.ID)
	fmt.Fprintf(stdout, "EVIDENCE %d item(s), %d finding(s)\n", len(trail.Evidence), len(trail.Findings))
	fmt.Fprintf(stdout, "SUMMARY  %s\n", trail.Summary)
	fmt.Fprintf(stdout, "OUTPUT   %s\n", *outPath)
	for _, warning := range validation.Warnings {
		fmt.Fprintln(stdout, "WARNING ", warning)
	}
	switch trail.Verdict {
	case model.VerdictAffected:
		return 2
	case model.VerdictUnknown:
		return 3
	default:
		return 0
	}
}

func runPropose(args []string, stdout, stderr io.Writer) int {
	set := flag.NewFlagSet("propose", flag.ContinueOnError)
	set.SetOutput(stderr)
	packPath := set.String("pack", "", "signed response-pack JSON")
	trailPath := set.String("trail", "", "affected PatchRover trail JSON")
	repositoryPath := set.String("repo", ".", "authorized repository directory")
	outPath := set.String("out", "patchrover-proposal.md", "proposal output path")
	force := set.Bool("force", false, "replace an existing output file")
	aiProvider := set.String("ai-provider", "none", "optional explanation provider: none, ollama, or openai-compatible")
	aiEndpoint := set.String("ai-endpoint", "", "explicit AI endpoint; Ollama defaults to loopback only")
	aiModel := set.String("ai-model", "", "already-installed local model or BYOK model name")
	aiKeyEnv := set.String("ai-key-env", "", "environment variable containing the BYOK endpoint key")
	if err := set.Parse(args); err != nil {
		return 1
	}
	if *packPath == "" || *trailPath == "" {
		fmt.Fprintln(stderr, "propose requires --pack and --trail")
		return 1
	}
	responsePack, validation, err := pack.LoadFile(*packPath)
	if err != nil {
		fmt.Fprintln(stderr, "pack validation failed:", err)
		return 1
	}
	if err := pack.RequireTrusted(validation); err != nil {
		fmt.Fprintln(stderr, "pack trust failed:", err)
		return 1
	}
	trail, err := loadTrail(*trailPath)
	if err != nil {
		fmt.Fprintln(stderr, "load trail:", err)
		return 1
	}
	if err := bindTrailToPack(trail, responsePack); err != nil {
		fmt.Fprintln(stderr, "trail validation failed:", err)
		return 1
	}
	remediation := proposal.Build(responsePack, trail, *repositoryPath)
	content := proposal.Markdown(remediation, responsePack.Spec.Sources)
	if *aiProvider != "none" {
		contextWithTimeout, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		explanation, err := ai.Explain(contextWithTimeout, ai.Config{
			Provider: *aiProvider, Endpoint: *aiEndpoint, Model: *aiModel, APIKeyEnv: *aiKeyEnv,
		}, remediation)
		if err != nil {
			fmt.Fprintln(stderr, "AI explanation failed without fallback:", err)
			return 1
		}
		content += "\n## Optional AI explanation — not evidence\n\n> This prose came from the explicitly configured provider. It did not influence the verdict, evidence, or patch. Verify it independently.\n\n" + strings.TrimSpace(explanation) + "\n"
	}
	if err := writeFile(*outPath, []byte(content), *force); err != nil {
		fmt.Fprintln(stderr, "write proposal:", err)
		return 1
	}
	fmt.Fprintf(stdout, "PROPOSAL %s\n", *outPath)
	fmt.Fprintf(stdout, "CHANGES  %d local diff(s)\n", len(remediation.Changes))
	fmt.Fprintln(stdout, "ACTION   Review manually; PatchRover did not change or deploy anything.")
	return 0
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	set := flag.NewFlagSet("verify", flag.ContinueOnError)
	set.SetOutput(stderr)
	packPath := set.String("pack", "", "signed response-pack JSON")
	trailPath := set.String("trail", "", "original affected PatchRover trail JSON")
	receiptPath := set.String("receipt", "patchrover-receipt.json", "receipt output path")
	identity := set.String("identity", "local-operator@patchrover", "self-asserted local receipt identity")
	force := set.Bool("force", false, "replace an existing output file")
	var evidence evidenceFlags
	addEvidenceFlags(set, &evidence)
	if err := set.Parse(args); err != nil {
		return 1
	}
	if *packPath == "" || *trailPath == "" || evidence.empty() {
		fmt.Fprintln(stderr, "verify requires --pack, --trail, and at least one fresh evidence source")
		return 1
	}
	responsePack, validation, err := pack.LoadFile(*packPath)
	if err != nil {
		fmt.Fprintln(stderr, "pack validation failed:", err)
		return 1
	}
	if err := pack.RequireTrusted(validation); err != nil {
		fmt.Fprintln(stderr, "pack trust failed:", err)
		return 1
	}
	originalTrail, err := loadTrail(*trailPath)
	if err != nil {
		fmt.Fprintln(stderr, "load trail:", err)
		return 1
	}
	if err := bindTrailToPack(originalTrail, responsePack); err != nil {
		fmt.Fprintln(stderr, "trail validation failed:", err)
		return 1
	}
	items, err := collect.All(evidence.options())
	if err != nil {
		fmt.Fprintln(stderr, "evidence collection failed:", err)
		return 1
	}
	verifiedTrail, err := engine.Assess(responsePack, items)
	if err != nil {
		fmt.Fprintln(stderr, "verification assessment failed:", err)
		return 1
	}
	verifiedTrail, err = engine.LinkPrevious(responsePack, verifiedTrail, originalTrail.ID)
	if err != nil {
		fmt.Fprintln(stderr, "link verification trail:", err)
		return 1
	}
	if verifiedTrail.Verdict != model.VerdictFixed {
		fmt.Fprintf(stderr, "verification did not reach fixed: %s — %s\n", verifiedTrail.Verdict, verifiedTrail.Summary)
		if verifiedTrail.Verdict == model.VerdictAffected {
			return 2
		}
		return 3
	}
	bundle, err := receipt.Create(responsePack, verifiedTrail, *identity)
	if err != nil {
		fmt.Fprintln(stderr, "create receipt:", err)
		return 1
	}
	if err := writeJSON(*receiptPath, bundle, *force); err != nil {
		fmt.Fprintln(stderr, "write receipt:", err)
		return 1
	}
	verification, err := receipt.Verify(bundle)
	if err != nil {
		fmt.Fprintln(stderr, "self-verify receipt:", err)
		return 1
	}
	fmt.Fprintln(stdout, "VERDICT  FIXED")
	fmt.Fprintf(stdout, "TRAIL    %s (previous %s)\n", verifiedTrail.ID, originalTrail.ID)
	fmt.Fprintf(stdout, "RECEIPT  %s\n", *receiptPath)
	fmt.Fprintf(stdout, "INTEGRITY %t\n", verification.IntegrityValid)
	fmt.Fprintf(stdout, "IDENTITY  trusted=%t (%s)\n", verification.IdentityTrusted, verification.Identity)
	fmt.Fprintln(stdout, "WARNING   A self-signed identity is not an external organizational trust proof.")
	return 0
}

func runReceipt(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "verify" {
		fmt.Fprintln(stderr, "usage: patchrover receipt verify <receipt.json>")
		return 1
	}
	data, err := os.ReadFile(args[1])
	if err != nil {
		fmt.Fprintln(stderr, "read receipt:", err)
		return 1
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var bundle model.ReceiptBundle
	if err := decoder.Decode(&bundle); err != nil {
		fmt.Fprintln(stderr, "decode receipt:", err)
		return 1
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		fmt.Fprintln(stderr, "decode receipt: trailing JSON values are not allowed")
		return 1
	}
	verification, err := receipt.Verify(bundle)
	if err != nil {
		fmt.Fprintln(stderr, "receipt invalid:", err)
		return 1
	}
	fmt.Fprintf(stdout, "INTEGRITY valid=%t\n", verification.IntegrityValid)
	fmt.Fprintf(stdout, "IDENTITY  trusted=%t identity=%s\n", verification.IdentityTrusted, verification.Identity)
	fmt.Fprintf(stdout, "RECEIPT   %s\n", verification.ReceiptID)
	fmt.Fprintf(stdout, "TRAIL     %s\n", verification.TrailID)
	fmt.Fprintf(stdout, "VERDICT   %s\n", strings.ToUpper(string(verification.Verdict)))
	fmt.Fprintln(stdout, "NOTE     ", verification.Message)
	return 0
}

func runPack(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "validate" {
		fmt.Fprintln(stderr, "usage: patchrover pack validate <pack-directory-or-json>")
		return 1
	}
	responsePack, validation, err := pack.LoadFile(args[1])
	if err != nil {
		fmt.Fprintln(stderr, "pack invalid:", err)
		return 1
	}
	fmt.Fprintf(stdout, "VALID     %s@%s\n", responsePack.Metadata.ID, responsePack.Metadata.Version)
	fmt.Fprintf(stdout, "DIGEST    %s\n", validation.PackDigest)
	fmt.Fprintf(stdout, "SIGNER    %s\n", validation.KeyID)
	fmt.Fprintf(stdout, "TRUST     %s\n", validation.Trust)
	fmt.Fprintf(stdout, "REVIEW    %s\n", responsePack.Metadata.ReviewState)
	fmt.Fprintf(stdout, "AUTHOR    %s\n", responsePack.Metadata.Author)
	fmt.Fprintf(stdout, "SOURCES   %d authoritative HTTPS source(s)\n", len(responsePack.Spec.Sources))
	if err := pack.RequireTrusted(validation); err != nil {
		fmt.Fprintln(stderr, "pack trust failed:", err)
		return 1
	}
	if info, statErr := os.Stat(args[1]); statErr == nil && info.IsDir() {
		if err := validatePackFixtures(args[1], responsePack); err != nil {
			fmt.Fprintln(stderr, "pack fixtures invalid:", err)
			return 1
		}
		fmt.Fprintln(stdout, "FIXTURES  affected, fixed, drift, and unknown corpus passed")
	} else {
		fmt.Fprintln(stdout, "FIXTURES  skipped (validate the pack directory to include its corpus)")
	}
	for _, warning := range validation.Warnings {
		fmt.Fprintln(stdout, "WARNING  ", warning)
	}
	return 0
}

func validatePackFixtures(packDirectory string, responsePack model.ResponsePack) error {
	expectations := []struct {
		name    string
		verdict model.Verdict
		drift   bool
	}{
		{"affected", model.VerdictAffected, false},
		{"fixed", model.VerdictFixed, false},
		{"drift", model.VerdictAffected, true},
		{"unknown", model.VerdictUnknown, false},
	}
	for _, expectation := range expectations {
		fixtureDirectory := filepath.Join(packDirectory, "fixtures", expectation.name)
		if err := validateFixtureSafety(fixtureDirectory); err != nil {
			return fmt.Errorf("%s: %w", expectation.name, err)
		}
		kubeSnapshot := filepath.Join(fixtureDirectory, "pods.json")
		if _, err := os.Stat(kubeSnapshot); err != nil {
			return fmt.Errorf("%s requires pods.json: %w", expectation.name, err)
		}
		evidence, err := collect.All(collect.Options{RepositoryPath: fixtureDirectory, KubeSnapshot: kubeSnapshot})
		if err != nil {
			return fmt.Errorf("%s collection: %w", expectation.name, err)
		}
		trail, err := engine.Assess(responsePack, evidence)
		if err != nil {
			return fmt.Errorf("%s assessment: %w", expectation.name, err)
		}
		if trail.Verdict != expectation.verdict || trail.Drift != expectation.drift {
			return fmt.Errorf("%s produced verdict=%s drift=%t, expected verdict=%s drift=%t", expectation.name, trail.Verdict, trail.Drift, expectation.verdict, expectation.drift)
		}
	}
	return nil
}

func validateFixtureSafety(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("fixture symlinks are not allowed: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 != 0 {
			return fmt.Errorf("fixture must be a non-executable regular file: %s", path)
		}
		if info.Size() > 1<<20 {
			return fmt.Errorf("fixture exceeds the 1 MiB safety limit: %s", path)
		}
		base := strings.ToLower(entry.Name())
		extension := strings.ToLower(filepath.Ext(base))
		if base != "dockerfile" && extension != ".json" && extension != ".txt" && extension != ".lock" && extension != ".toml" {
			return fmt.Errorf("unsupported fixture file type: %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		upper := strings.ToUpper(string(data))
		if strings.Contains(upper, "BEGIN PRIVATE KEY") || strings.Contains(upper, "BEGIN OPENSSH PRIVATE KEY") {
			return fmt.Errorf("fixture appears to contain private key material: %s", path)
		}
		return nil
	})
}

func loadTrail(path string) (model.Trail, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return model.Trail{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var trail model.Trail
	if err := decoder.Decode(&trail); err != nil {
		return model.Trail{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return model.Trail{}, errors.New("trail contains trailing JSON values")
	}
	if trail.APIVersion != model.APIVersion || trail.Kind != "Trail" || trail.ID == "" || trail.PackDigest == "" {
		return model.Trail{}, errors.New("invalid PatchRover trail")
	}
	return trail, nil
}

func bindTrailToPack(trail model.Trail, responsePack model.ResponsePack) error {
	return engine.ValidateTrail(responsePack, trail)
}

func writeJSON(path string, value any, force bool) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFile(path, data, force)
}

func writeFile(path string, data []byte, force bool) error {
	if path == "" || strings.ContainsAny(path, "\x00") {
		return errors.New("invalid output path")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("refusing non-regular or symlink output path %s", path)
		}
		if !force {
			return fmt.Errorf("%s already exists; choose another path or pass --force", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(path)
	if parent != "." {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return err
		}
	}
	flags := os.O_WRONLY | os.O_CREATE
	if force {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}
	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func printHelp(output io.Writer) {
	fmt.Fprintln(output, `PatchRover — Track. Fix. Prove.

Usage:
  patchrover assess --pack PACK --repo REPOSITORY [evidence flags]
  patchrover propose --pack PACK --trail TRAIL [--repo REPOSITORY]
  patchrover verify --pack PACK --trail TRAIL [fresh evidence flags]
  patchrover receipt verify RECEIPT
  patchrover pack validate PACK
  patchrover agent run --config agent.json [--once]
  patchrover agent status --state state.json
  patchrover agent review --config agent.json --action ACTION_ID
  patchrover version

Evidence flags:
  --repo PATH             authorized repository directory
  --sbom FILE             CycloneDX or SPDX JSON
  --image REF             OCI image reference or digest
  --evidence FILE         explicit PatchRover evidence JSON
  --kube-context NAME     explicit read-only kubectl context
  --kube-snapshot FILE    offline Kubernetes PodList JSON

Use propose mode to require an interactive review before each fix. The review command shows the
exact change and applies it only after the operator types yes. PatchRover never changes human
passwords, never treats missing evidence as safe, never auto-approves, and never deploys production workloads.`)
}
