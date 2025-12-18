//go:build windows

package main

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
	"os/exec"
	"strings"
	"time"
)

const (
	maxInputBytes         = 5_000_000
	defaultTimeoutSeconds = 1800
	defaultActionName     = "windows_update_remediation"
)

type remediationResult struct {
	Action     string `json:"action"`
	Approved   bool   `json:"approved"`
	Executed   bool   `json:"executed"`
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt"`
	ExitCode   int    `json:"exitCode"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	Error      string `json:"error"`
	Reason     string `json:"reason"`
	Security   secOut `json:"securityContext"`
	Command    string `json:"command"`
}

type commandSpec struct {
	name string
	exe  string
	args []string
}

type triageInput struct {
	Summary   string       `json:"summary"`
	Signals   []any        `json:"signals"`
	RootCause string       `json:"rootCause"`
	Tags      []string     `json:"tags"`
	Plan      recoveryPlan `json:"recovery_plan"`
	Actions   []string     `json:"recommendedActions"`
	Security  secIn        `json:"security"`
}

type secIn struct {
	MissingKBs  []string `json:"missing_kbs"`
	RelatedCVEs []string `json:"related_cves"`
}

type secOut struct {
	MissingKBs  []string `json:"missing_kbs"`
	RelatedCVEs []string `json:"related_cves"`
}

func main() {
	timeoutSeconds := flag.Int("timeout", defaultTimeoutSeconds, "timeout per action in seconds")
	flag.Parse()

	if *timeoutSeconds <= 0 {
		*timeoutSeconds = defaultTimeoutSeconds
	}

	rawInput, err := readStdinLimited(maxInputBytes)
	if err != nil {
		exitFatal(err)
	}

	triage, err := parseTriage(rawInput)
	if err != nil {
		exitFatal(err)
	}

	now := time.Now().UTC()
	result := remediationResult{
		Action:     defaultActionName,
		Approved:   false,
		Executed:   false,
		StartedAt:  now.Format(time.RFC3339),
		FinishedAt: now.Format(time.RFC3339),
		ExitCode:   0,
		Stdout:     "",
		Stderr:     "",
		Error:      "",
		Security: secOut{
			MissingKBs:  triage.Security.MissingKBs,
			RelatedCVEs: triage.Security.RelatedCVEs,
		},
	}

	applicable, reason := isWindowsUpdateIssue(triage)
	if !applicable {
		result.Error = "not applicable"
		result.Reason = reason
		outputResult(result)
		return
	}

	spec, actionReason := chooseAction(triage)
	result.Action = spec.name
	result.Command = joinCommand(spec)
	if strings.TrimSpace(reason) != "" && strings.TrimSpace(actionReason) != "" {
		result.Reason = reason + "; " + actionReason
	} else if strings.TrimSpace(actionReason) != "" {
		result.Reason = actionReason
	} else {
		result.Reason = reason
	}

	fmt.Fprintf(os.Stderr, "Proposed action: %s. Approve? (yes/no): ", spec.name)
	approved, err := askApproval()
	if err != nil {
		result.Error = fmt.Sprintf("approval failed: %v", err)
		outputResult(result)
		return
	}
	result.Approved = approved
	if !approved {
		result.Error = "not approved"
		outputResult(result)
		return
	}

	if missing := missingTools(spec); len(missing) > 0 {
		result.Error = "required tools missing: " + strings.Join(missing, ", ")
		outputResult(result)
		return
	}

	execTimeout := time.Duration(*timeoutSeconds) * time.Second
	runRes := executeCommand(spec, execTimeout)
	result.Executed = true
	result.StartedAt = runRes.StartedAt
	result.ExitCode = runRes.ExitCode
	result.Stdout = runRes.Stdout
	result.Stderr = runRes.Stderr
	result.Error = runRes.Error
	result.FinishedAt = runRes.FinishedAt

	outputResult(result)
}

func readStdinLimited(limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = maxInputBytes
	}
	lr := &io.LimitedReader{R: os.Stdin, N: limit + 1}
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("stdin exceeds limit (%d bytes)", limit)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("stdin is empty")
	}
	return data, nil
}

type recoveryPlan struct {
	RecommendedAction string `json:"recommended_action"`
	ExactCommand      string `json:"exact_command"`
}

func parseTriage(raw []byte) (triageInput, error) {
	var t triageInput
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&t); err != nil {
		return t, fmt.Errorf("parse triage JSON: %w", err)
	}
	return t, nil
}

func isWindowsUpdateIssue(t triageInput) (bool, string) {
	keywords := []string{
		"windows update",
		"windowsupdateclient",
		"windowsupdate",
		"0x800f",
		"cbs",
		"dism",
		"sfc",
	}

	for _, candidate := range collectStrings(t) {
		ls := strings.ToLower(candidate)
		for _, kw := range keywords {
			if strings.Contains(ls, kw) {
				return true, "windows update signals detected"
			}
		}
	}
	if len(t.Security.MissingKBs) > 0 {
		return true, "missing_kbs present in triage"
	}
	return false, "no windows update signals detected"
}

func collectStrings(t triageInput) []string {
	var out []string

	addIfString := func(v string) {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}

	addIfString(t.Summary)
	addIfString(t.RootCause)
	for _, tag := range t.Tags {
		addIfString(tag)
	}
	addStringsFromValue(t.Signals, &out)
	for _, act := range t.Actions {
		addIfString(act)
	}
	addIfString(t.Plan.RecommendedAction)
	addIfString(t.Plan.ExactCommand)

	return out
}

func addStringsFromValue(val []any, dest *[]string) {
	for _, v := range val {
		switch s := v.(type) {
		case string:
			if strings.TrimSpace(s) != "" {
				*dest = append(*dest, s)
			}
		case []any:
			addStringsFromValue(s, dest)
		case map[string]any:
			for _, inner := range s {
				if str, ok := inner.(string); ok && strings.TrimSpace(str) != "" {
					*dest = append(*dest, str)
				}
			}
		}
	}
}

func chooseAction(t triageInput) (commandSpec, string) {
	dism := commandSpec{name: "dism_restorehealth", exe: "dism.exe", args: []string{"/online", "/cleanup-image", "/restorehealth"}}
	sfc := commandSpec{name: "sfc_scannow", exe: "sfc.exe", args: []string{"/scannow"}}
	cacheReset := commandSpec{name: "reset_update_cache", exe: "powershell.exe", args: []string{
		"-NoProfile", "-NonInteractive", "-Command",
		`$ErrorActionPreference="Stop";
Stop-Service -Name wuauserv -Force;
Stop-Service -Name bits -Force;
$path="$env:SystemRoot\SoftwareDistribution";
$backup="$path.bak-"+(Get-Date -Format "yyyyMMddHHmmss");
if (Test-Path $path) { Rename-Item -Path $path -NewName $backup -Force };
Start-Service -Name bits;
Start-Service -Name wuauserv;
Write-Output "SoftwareDistribution reset completed: renamed to $backup";`,
	}}

	choices := []string{}

	if strings.TrimSpace(t.Plan.RecommendedAction) != "" {
		choices = append(choices, t.Plan.RecommendedAction)
	}
	if strings.TrimSpace(t.Plan.ExactCommand) != "" {
		choices = append(choices, t.Plan.ExactCommand)
	}
	for _, item := range t.Actions {
		if strings.TrimSpace(item) != "" {
			choices = append(choices, item)
		}
	}

	for _, choice := range choices {
		normalized := strings.ToLower(strings.TrimSpace(choice))
		switch normalized {
		case "dism_restore_health", "dism_restorehealth":
			return dism, "recommended action requested DISM"
		case "sfc_scannow":
			return sfc, "recommended action requested SFC"
		case "reset_update_cache", "clear_update_cache", "reset windows update cache":
			return cacheReset, "recommended action requested cache reset"
		default:
			if strings.Contains(normalized, "dism") && strings.Contains(normalized, "restorehealth") {
				return dism, "recommended action matched DISM"
			}
			if strings.Contains(normalized, "sfc") {
				return sfc, "recommended action matched SFC"
			}
			if strings.Contains(normalized, "cache") && strings.Contains(normalized, "update") {
				return cacheReset, "recommended action matched cache reset"
			}
		}
	}

	if len(t.Security.MissingKBs) > 0 {
		return dism, "missing KBs detected; attempting repair via DISM"
	}

	return dism, "default repair: DISM"
}

func askApproval() (bool, error) {
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "yes" || line == "y", nil
}

func missingTools(spec commandSpec) []string {
	tools := map[string]bool{spec.exe: true}
	var missing []string
	for tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}
	return missing
}

func executeCommand(spec commandSpec, timeout time.Duration) remediationResult {
	start := time.Now().UTC()
	res := remediationResult{
		Action:     spec.name,
		Command:    joinCommand(spec),
		Approved:   true,
		Executed:   true,
		StartedAt:  start.Format(time.RFC3339),
		FinishedAt: start.Format(time.RFC3339),
		ExitCode:   0,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, spec.exe, spec.args...)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	res.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	res.Stdout = stdoutBuf.String()
	res.Stderr = stderrBuf.String()

	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			res.Error = "timeout exceeded"
			res.ExitCode = -1
			return res
		}
		res.Error = err.Error()
		if exitErr, ok := err.(*exec.ExitError); ok {
			res.ExitCode = exitErr.ExitCode()
		} else {
			res.ExitCode = -1
		}
	}

	return res
}

func outputResult(res remediationResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(res); err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode JSON: %v\n", err)
		os.Exit(2)
	}
}

func exitFatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(2)
}

func joinCommand(spec commandSpec) string {
	if len(spec.args) == 0 {
		return spec.exe
	}
	return spec.exe + " " + strings.Join(spec.args, " ")
}
