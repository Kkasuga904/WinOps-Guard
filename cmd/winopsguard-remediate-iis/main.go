//go:build windows

package main

import (
	"bufio"
	"bytes"
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
	maxInputBytes = 5_000_000
	actionName    = "iisreset"
)

type triageInput struct {
	Summary string          `json:"summary"`
	Signals json.RawMessage `json:"signals"`
}

type result struct {
	Action     string `json:"action"`
	Approved   bool   `json:"approved"`
	Executed   bool   `json:"executed"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	ExitCode   int    `json:"exitCode"`
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt"`
	Error      string `json:"error,omitempty"`
}

func main() {
	flag.Parse()

	res := result{
		Action:     actionName,
		Approved:   false,
		Executed:   false,
		ExitCode:   0,
		StartedAt:  "",
		FinishedAt: "",
	}

	input, err := readStdinLimited(maxInputBytes)
	if err != nil {
		res.Error = err.Error()
		output(res)
		return
	}

	triage, err := parseTriage(input)
	if err != nil {
		res.Error = err.Error()
		output(res)
		return
	}

	if !isIISIssue(triage) {
		res.Error = "no IIS-related issue detected; no action proposed"
		output(res)
		return
	}

	fmt.Fprint(os.Stderr, "Proposed action: restart IIS (iisreset). Approve? (yes/no): ")
	approved, err := askApproval()
	if err != nil {
		res.Error = fmt.Sprintf("approval failed: %v", err)
		output(res)
		return
	}
	res.Approved = approved
	if !approved {
		output(res)
		return
	}

	if err := ensureIISPresent(); err != nil {
		res.Error = err.Error()
		output(res)
		return
	}

	start := time.Now().UTC()
	stdout, stderr, exitCode, execErr := runIISReset()
	res.StartedAt = start.Format(time.RFC3339)
	res.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	res.Executed = true
	res.Stdout = stdout
	res.Stderr = stderr
	res.ExitCode = exitCode
	if execErr != nil {
		res.Error = execErr.Error()
	}

	output(res)
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

func parseTriage(raw []byte) (triageInput, error) {
	var t triageInput
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&t); err != nil {
		return t, fmt.Errorf("parse triage JSON: %w", err)
	}
	return t, nil
}

func isIISIssue(t triageInput) bool {
	s := strings.ToLower(t.Summary)
	if strings.Contains(s, "iis") || strings.Contains(s, "w3svc") || strings.Contains(s, "world wide web") || strings.Contains(s, "app pool") || strings.Contains(s, "application pool") {
		return true
	}
	// Inspect signals if present
	if len(t.Signals) == 0 || string(t.Signals) == "null" {
		return false
	}
	var signals []any
	if err := json.Unmarshal(t.Signals, &signals); err != nil {
		return false
	}
	for _, sig := range signals {
		switch v := sig.(type) {
		case string:
			ls := strings.ToLower(v)
			if strings.Contains(ls, "iis") || strings.Contains(ls, "w3svc") || strings.Contains(ls, "world wide web") {
				return true
			}
		case map[string]any:
			for _, val := range v {
				if str, ok := val.(string); ok {
					ls := strings.ToLower(str)
					if strings.Contains(ls, "iis") || strings.Contains(ls, "w3svc") || strings.Contains(ls, "world wide web") {
						return true
					}
				}
			}
		}
	}
	return false
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

func ensureIISPresent() error {
	if _, err := exec.LookPath(actionName); err != nil {
		return errors.New("iisreset not found; IIS may not be installed or PATH is missing system32")
	}
	return nil
}

func runIISReset() (string, string, int, error) {
	cmd := exec.Command(actionName)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	stdout := stdoutBuf.String()
	stderr := stderrBuf.String()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
		return stdout, stderr, exitCode, err
	}
	return stdout, stderr, exitCode, nil
}

func output(res result) {
	// Fill timestamps if missing
	now := time.Now().UTC().Format(time.RFC3339)
	if res.StartedAt == "" {
		res.StartedAt = now
	}
	if res.FinishedAt == "" {
		res.FinishedAt = now
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	enc.Encode(res)
}
