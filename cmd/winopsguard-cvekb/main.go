package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	maxInputBytes = 5_000_000
)

type assessment struct {
	Kind        string           `json:"kind"`
	GeneratedAt string           `json:"generatedAt"`
	Items       []assessmentItem `json:"items"`
	Errors      []string         `json:"errors"`
}

type assessmentItem struct {
	CVE         string   `json:"cve"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	ProductHint []string `json:"productHints"`
	KBCands     []string `json:"kbCandidates"`
	Notes       string   `json:"notes"`
}

var (
	reCVE = regexp.MustCompile(`CVE-\d{4}-\d+`)
	reKB  = regexp.MustCompile(`KB\d{6,7}`)
)

func main() {
	flag.Parse()

	raw, err := readStdinLimited(maxInputBytes)
	if err != nil {
		exitErr(err)
	}

	text, err := extractText(raw)
	if err != nil {
		exitErr(err)
	}

	cvss := uniqueStrings(reCVE.FindAllString(text, -1))
	kbs := uniqueStrings(reKB.FindAllString(text, -1))

	res := assessment{
		Kind:        "cve_kb_assessment",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Errors:      []string{},
	}

	if len(cvss) == 0 {
		res.Errors = append(res.Errors, "no CVE identifiers found in input")
		output(res)
		return
	}

	for _, cve := range cvss {
		item := assessmentItem{
			CVE:         cve,
			Title:       "",
			Severity:    "Unknown",
			ProductHint: []string{},
			KBCands:     kbs,
		}
		if len(kbs) == 0 {
			item.Notes = "KB不明。MSRC/ADV参照が必要"
		} else {
			item.Notes = "KB candidates extracted from text"
		}
		res.Items = append(res.Items, item)
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

func extractText(raw []byte) (string, error) {
	trim := bytes.TrimSpace(raw)
	if len(trim) == 0 {
		return "", errors.New("input is empty")
	}
	// try JSON with cveText field
	var obj map[string]any
	if err := json.Unmarshal(trim, &obj); err == nil {
		if cveText, ok := obj["cveText"].(string); ok && strings.TrimSpace(cveText) != "" {
			return cveText, nil
		}
	}
	return string(trim), nil
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		if s == "" {
			continue
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func output(v assessment) {
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
