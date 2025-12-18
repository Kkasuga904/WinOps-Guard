//go:build windows

package main

import (
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
	defaultTimeoutSeconds = 60
)

type inputAssessment struct {
	Kind   string      `json:"kind"`
	Items  []inputItem `json:"items"`
	Errors []string    `json:"errors"`
}

type inputItem struct {
	CVE      string   `json:"cve"`
	Severity string   `json:"severity"`
	KBCands  []string `json:"kbCandidates"`
}

type outputAssessment struct {
	Kind        string         `json:"kind"`
	GeneratedAt string         `json:"generatedAt"`
	Items       []hotfixResult `json:"items"`
	Errors      []string       `json:"errors"`
}

type hotfixResult struct {
	CVE       string `json:"cve"`
	KB        string `json:"kb"`
	Installed bool   `json:"installed"`
	Evidence  string `json:"evidence"`
	Risk      string `json:"risk"`
}

func main() {
	timeoutSeconds := flag.Int("timeout", defaultTimeoutSeconds, "timeout for Get-HotFix in seconds")
	flag.Parse()

	if *timeoutSeconds <= 0 {
		*timeoutSeconds = defaultTimeoutSeconds
	}

	raw, err := readStdinLimited(maxInputBytes)
	if err != nil {
		exitErr(err)
	}

	inp, err := parseInput(raw)
	if err != nil {
		exitErr(err)
	}

	res := outputAssessment{
		Kind:        "hotfix_assessment",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Items:       []hotfixResult{},
		Errors:      []string{},
	}

	if len(inp.Items) == 0 {
		res.Errors = append(res.Errors, "no assessment items found")
		output(res)
		return
	}

	if _, err := exec.LookPath("powershell.exe"); err != nil {
		res.Errors = append(res.Errors, "powershell.exe not found in PATH")
		output(res)
		return
	}

	installedSet, err := queryInstalledKBs(time.Duration(*timeoutSeconds) * time.Second)
	if err != nil {
		res.Errors = append(res.Errors, err.Error())
		output(res)
		return
	}

	for _, item := range inp.Items {
		risk := item.Severity
		if strings.TrimSpace(risk) == "" {
			risk = "Unknown"
		}
		for _, kb := range item.KBCands {
			installed := installedSet[strings.ToUpper(kb)]
			ev := "Get-HotFix checked"
			if installed {
				ev = "Get-HotFix matched"
			}
			res.Items = append(res.Items, hotfixResult{
				CVE:       item.CVE,
				KB:        kb,
				Installed: installed,
				Evidence:  ev,
				Risk:      risk,
			})
		}
	}

	output(res)
}

func readStdinLimited(limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = maxInputBytes
	}
	data, err := io.ReadAll(&io.LimitedReader{R: os.Stdin, N: limit + 1})
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

func parseInput(raw []byte) (inputAssessment, error) {
	var in inputAssessment
	if err := json.Unmarshal(raw, &in); err != nil {
		return in, fmt.Errorf("parse input JSON: %w", err)
	}
	if strings.TrimSpace(in.Kind) == "" {
		in.Kind = "cve_kb_assessment"
	}
	return in, nil
}

func queryInstalledKBs(timeout time.Duration) (map[string]bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	script := `Get-HotFix | Select-Object -ExpandProperty HotFixID`
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("Get-HotFix timeout exceeded")
		}
		return nil, fmt.Errorf("Get-HotFix failed: %s", strings.TrimSpace(buf.String()))
	}

	lines := strings.Split(buf.String(), "\n")
	set := make(map[string]bool)
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		set[strings.ToUpper(trim)] = true
	}
	return set, nil
}

func output(v outputAssessment) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode JSON: %v\n", err)
		os.Exit(2)
	}
}

func exitErr(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(2)
}
