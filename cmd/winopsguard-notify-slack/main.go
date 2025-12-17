package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultTimeoutSeconds = 10
	defaultMaxBytes       = 5_000_000
	maxSignals            = 10
	maxActions            = 3
	maxSummaryLen         = 300
	maxSignalLen          = 200
)

type triageAction struct {
	Title    string `json:"title"`
	Commands []struct {
		Cmd  string   `json:"cmd"`
		Args []string `json:"args"`
	} `json:"commands"`
}

type triagePayload struct {
	Severity   string         `json:"severity"`
	Confidence float64        `json:"confidence"`
	Summary    string         `json:"summary"`
	Signals    []string       `json:"signals"`
	Actions    []triageAction `json:"actions"`
	Raw        map[string]any `json:"raw"`
}

type slackPayload struct {
	Text string `json:"text"`
}

func main() {
	dryRun := flag.Bool("dry-run", false, "Print Slack payload instead of sending")
	timeoutSec := flag.Int("timeout", defaultTimeoutSeconds, "HTTP timeout in seconds")
	flag.Parse()

	body, err := readStdinLimited(defaultMaxBytes)
	if err != nil {
		exitErr(err, 2)
	}

	tpayload, err := parseTriage(body)
	if err != nil {
		exitErr(err, 2)
	}

	severity := normalizeSeverity(tpayload.Severity)
	if severityRank(severity) == severityRank("info") {
		// info => no post, success.
		return
	}

	webhook := strings.TrimSpace(os.Getenv("SLACK_WEBHOOK_URL"))
	if webhook == "" {
		exitErr(errors.New("SLACK_WEBHOOK_URL is not set"), 2)
	}

	payload := buildSlackPayload(severity, tpayload)

	if *dryRun {
		if err := outputJSON(payload); err != nil {
			exitErr(err, 2)
		}
		return
	}

	client := &http.Client{Timeout: time.Duration(*timeoutSec) * time.Second}
	if err := postSlack(client, webhook, payload); err != nil {
		exitErr(err, 2)
	}
}

func readStdinLimited(limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = defaultMaxBytes
	}
	lr := &io.LimitedReader{R: os.Stdin, N: limit + 1}
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("stdin exceeds max bytes (%d)", limit)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("stdin is empty")
	}
	return data, nil
}

func parseTriage(raw []byte) (triagePayload, error) {
	var tp triagePayload
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&tp); err != nil {
		return tp, fmt.Errorf("stdin JSON decode: %w", err)
	}
	return tp, nil
}

func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "warning", "warn":
		return "warning"
	case "critical", "crit":
		return "critical"
	default:
		return "info"
	}
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 3
	case "warning":
		return 2
	default:
		return 1
	}
}

func buildSlackPayload(sev string, tp triagePayload) slackPayload {
	conf := tp.Confidence
	if conf < 0 {
		conf = 0
	}
	textBuilder := &strings.Builder{}
	fmt.Fprintf(textBuilder, "WinOps Guard Triage: %s (confidence=%.2f)\n", strings.ToUpper(sev), conf)

	summary := truncate(tp.Summary, maxSummaryLen)
	if summary != "" {
		fmt.Fprintf(textBuilder, "Summary: %s\n", summary)
	}

	if len(tp.Signals) > 0 {
		fmt.Fprintf(textBuilder, "Signals:\n")
		for i, sig := range tp.Signals {
			if i >= maxSignals {
				break
			}
			fmt.Fprintf(textBuilder, "- %s\n", truncate(sig, maxSignalLen))
		}
	}

	if len(tp.Actions) > 0 {
		fmt.Fprintf(textBuilder, "Actions:\n")
		for i, act := range tp.Actions {
			if i >= maxActions {
				break
			}
			title := truncate(act.Title, maxSignalLen)
			if title == "" {
				title = "(no title)"
			}
			fmt.Fprintf(textBuilder, "- %s\n", title)
		}
	}

	return slackPayload{Text: textBuilder.String()}
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func postSlack(client *http.Client, webhook string, payload slackPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, webhook, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post slack: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func outputJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode payload: %w", err)
	}
	_, err = os.Stdout.Write(b)
	return err
}

func exitErr(err error, code int) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	if code == 0 {
		code = 1
	}
	os.Exit(code)
}
