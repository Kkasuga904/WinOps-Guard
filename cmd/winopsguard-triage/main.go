package main

import (
	"bytes"
	"context"
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
	defaultProvider    = "openai"
	defaultOpenAIModel = "gpt-4o-mini"
	defaultGeminiModel = "gemini-1.5-flash"
	defaultTimeout     = 30 * time.Second
	defaultMaxBytes    = 5_000_000
	openAIEndpoint     = "https://api.openai.com/v1/chat/completions"
	geminiEndpointFmt  = "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s"
	maxOutputTokens    = 1200
)

const systemPrompt = `You are a Senior Windows System Engineer specializing in OS servicing and update recovery.
Analyze Windows Event Logs (Setup, System, WindowsUpdateClient) to diagnose update failures.

Diagnostic goals:
1) Error Identification: extract hex codes (e.g., 0x800f0922, 0x8024200d).
2) Component Health: decide if Component Store (WinSxS) is corrupted vs transient network/service issue.
3) Recovery Path: decide if DISM/SFC are appropriate.

Remediation logic:
- If logs indicate "Component Store Corrupt" or "Manifest missing": suggest DISM RestoreHealth.
- If logs indicate "File not found" or "Integrity violation": suggest SFC Scannow.
- If unsure: suggest Manual Investigation and do NOT provide a command.

Safety:
- Never suggest registry edits or manual file deletions.
- Only suggest idempotent, safe-to-rerun commands.
Output must be JSON only.`

const userPromptTemplate = `Analyze the following signals provided in JSON:
%s

If security findings (CVE/KB) are present, incorporate them into the reasoning.
Respond with JSON using this schema:
{
  "incident_type": "windows_update_failure",
  "error_code": "0xXXXXXXXX",
  "analysis": "Briefly explain why the update failed based on logs.",
  "severity": "Critical",
  "recovery_plan": {
    "recommended_action": "dism_restore_health | sfc_scannow | manual_check",
    "rationale": "Why this specific tool is the best first step.",
    "exact_command": "dism /online /cleanup-image /restorehealth"
  },
  "confidence_score": 0.0 to 1.0
}`

func main() {
	provider := flag.String("provider", defaultProvider, `LLM provider ("openai" or "gemini")`)
	model := flag.String("model", "", "Model name (defaults per provider)")
	timeout := flag.Duration("timeout", defaultTimeout, "HTTP timeout (e.g. 30s, 60s)")
	maxBytes := flag.Int("max-bytes", defaultMaxBytes, "Maximum stdin bytes to read")
	flag.Parse()

	rawInput, err := readStdinLimited(int64(*maxBytes))
	if err != nil {
		exitErr(err)
	}

	normalizedInput, secCtx, err := normalizeInput(rawInput)
	if err != nil {
		exitErr(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	userPrompt := buildUserPrompt(normalizedInput, secCtx)
	res, err := dispatchLLM(ctx, *provider, *model, userPrompt)
	if err != nil {
		exitErr(err)
	}

	if err := outputFormattedJSON(res, secCtx); err != nil {
		exitErr(err)
	}
}

func readStdinLimited(limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = defaultMaxBytes
	}
	lr := &io.LimitedReader{R: os.Stdin, N: limit + 1}
	buf, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	if int64(len(buf)) > limit {
		return nil, fmt.Errorf("stdin exceeds max-bytes (%d)", limit)
	}
	if len(bytes.TrimSpace(buf)) == 0 {
		return nil, errors.New("stdin is empty")
	}
	return buf, nil
}

type securityContext struct {
	MissingKBs     []string `json:"missing_kbs"`
	RelatedCVEs    []string `json:"related_cves"`
	Summary        string   `json:"summary"`
	Recommendation string   `json:"recommendation"`
}

func normalizeInput(raw []byte) (string, securityContext, error) {
	var sec securityContext
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "", sec, errors.New("stdin is empty")
	}
	var anyVal any
	if err := json.Unmarshal(trimmed, &anyVal); err != nil {
		return "", sec, fmt.Errorf("stdin must be JSON: %w", err)
	}
	sec = extractSecurity(anyVal)
	return string(trimmed), sec, nil
}

func extractSecurity(val any) securityContext {
	var sec securityContext
	switch v := val.(type) {
	case map[string]any:
		sec = extractSecurityFromMap(v)
	case []any:
		for _, it := range v {
			part := extractSecurity(it)
			sec.MissingKBs = append(sec.MissingKBs, part.MissingKBs...)
			sec.RelatedCVEs = append(sec.RelatedCVEs, part.RelatedCVEs...)
		}
	}
	sec.MissingKBs = uniqueStrings(sec.MissingKBs)
	sec.RelatedCVEs = uniqueStrings(sec.RelatedCVEs)
	if len(sec.MissingKBs) > 0 {
		sec.Summary = "Missing KBs detected"
		sec.Recommendation = "Install missing KBs; if update failing, run DISM/SFC with approval"
	} else if len(sec.RelatedCVEs) > 0 {
		sec.Summary = "Security advisories detected"
		sec.Recommendation = "Review CVEs and ensure corresponding KBs are installed"
	}
	return sec
}

func extractSecurityFromMap(m map[string]any) securityContext {
	var sec securityContext
	if kind, ok := m["kind"].(string); ok {
		switch strings.ToLower(kind) {
		case "hotfix_assessment":
			if items, ok := m["items"].([]any); ok {
				for _, it := range items {
					if obj, ok := it.(map[string]any); ok {
						if kb, ok := obj["kb"].(string); ok {
							if installed, ok := obj["installed"].(bool); ok && !installed {
								sec.MissingKBs = append(sec.MissingKBs, kb)
							}
						}
						if cve, ok := obj["cve"].(string); ok && strings.TrimSpace(cve) != "" {
							sec.RelatedCVEs = append(sec.RelatedCVEs, cve)
						}
					}
				}
			}
		case "cve_kb_assessment":
			if items, ok := m["items"].([]any); ok {
				for _, it := range items {
					if obj, ok := it.(map[string]any); ok {
						if cve, ok := obj["cve"].(string); ok && strings.TrimSpace(cve) != "" {
							sec.RelatedCVEs = append(sec.RelatedCVEs, cve)
						}
						if kbs, ok := obj["kbCandidates"].([]any); ok {
							for _, kb := range kbs {
								if s, ok := kb.(string); ok && strings.TrimSpace(s) != "" {
									sec.MissingKBs = append(sec.MissingKBs, s)
								}
							}
						}
					}
				}
			}
		}
	}
	if secContext, ok := m["security"].(map[string]any); ok {
		if mkb, ok := secContext["missing_kbs"].([]any); ok {
			for _, kb := range mkb {
				if s, ok := kb.(string); ok && strings.TrimSpace(s) != "" {
					sec.MissingKBs = append(sec.MissingKBs, s)
				}
			}
		}
		if rc, ok := secContext["related_cves"].([]any); ok {
			for _, cve := range rc {
				if s, ok := cve.(string); ok && strings.TrimSpace(s) != "" {
					sec.RelatedCVEs = append(sec.RelatedCVEs, s)
				}
			}
		}
	}
	return sec
}

func dispatchLLM(ctx context.Context, provider, model, userPrompt string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(provider))
	switch p {
	case "openai", "":
		return callOpenAI(ctx, chooseModel(model, defaultOpenAIModel), userPrompt)
	case "gemini":
		return callGemini(ctx, chooseModel(model, defaultGeminiModel), userPrompt)
	default:
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}
}

func buildUserPrompt(signalsJSON string, sec securityContext) string {
	if len(sec.MissingKBs) == 0 && len(sec.RelatedCVEs) == 0 {
		return fmt.Sprintf(userPromptTemplate, signalsJSON)
	}
	secBytes, _ := json.Marshal(sec)
	return fmt.Sprintf(userPromptTemplate, signalsJSON) + "\nSecurity context:\n" + string(secBytes)
}

func callOpenAI(ctx context.Context, model, userPrompt string) (string, error) {
	apiKey := strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
	if apiKey == "" {
		return "", errors.New("OPENAI_API_KEY is not set")
	}

	reqBody := struct {
		Model       string  `json:"model"`
		Temperature float64 `json:"temperature"`
		MaxTokens   int     `json:"max_tokens,omitempty"`
		Messages    []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}{
		Model:       model,
		Temperature: 0,
		MaxTokens:   maxOutputTokens,
		Messages: []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("encode OpenAI request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, openAIEndpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create OpenAI request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 0}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("OpenAI request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read OpenAI response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("OpenAI HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var decoded struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return "", fmt.Errorf("decode OpenAI response: %w", err)
	}
	if len(decoded.Choices) == 0 {
		return "", errors.New("OpenAI response has no choices")
	}

	return decoded.Choices[0].Message.Content, nil
}

func callGemini(ctx context.Context, model, userPrompt string) (string, error) {
	apiKey := strings.TrimSpace(os.Getenv("GEMINI_API_KEY"))
	if apiKey == "" {
		return "", errors.New("GEMINI_API_KEY is not set")
	}

	reqBody := struct {
		SystemInstruction struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"systemInstruction"`
		Contents []struct {
			Role  string `json:"role,omitempty"`
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"contents"`
		GenerationConfig struct {
			Temperature     float64 `json:"temperature,omitempty"`
			MaxOutputTokens int     `json:"maxOutputTokens,omitempty"`
		} `json:"generationConfig,omitempty"`
	}{}

	reqBody.SystemInstruction.Parts = []struct {
		Text string `json:"text"`
	}{{Text: systemPrompt}}
	reqBody.Contents = []struct {
		Role  string `json:"role,omitempty"`
		Parts []struct {
			Text string `json:"text"`
		} `json:"parts"`
	}{
		{
			Role: "user",
			Parts: []struct {
				Text string `json:"text"`
			}{{Text: userPrompt}},
		},
	}
	reqBody.GenerationConfig.Temperature = 0
	reqBody.GenerationConfig.MaxOutputTokens = maxOutputTokens

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("encode Gemini request: %w", err)
	}

	url := fmt.Sprintf(geminiEndpointFmt, model, apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create Gemini request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 0}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Gemini request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read Gemini response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("Gemini HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var decoded struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return "", fmt.Errorf("decode Gemini response: %w", err)
	}
	if len(decoded.Candidates) == 0 || len(decoded.Candidates[0].Content.Parts) == 0 {
		return "", errors.New("Gemini response has no text")
	}
	return decoded.Candidates[0].Content.Parts[0].Text, nil
}

func outputFormattedJSON(raw string, secCtx securityContext) error {
	// Markdownのコードブロック（```json ... ```）を除去する処理を追加
	cleaned := cleanLLMOutput(raw)

	rawBytes := bytes.TrimSpace([]byte(cleaned))
	if len(rawBytes) == 0 {
		return errors.New("LLM response is empty")
	}

	var obj map[string]any
	if err := json.Unmarshal(rawBytes, &obj); err != nil {
		return fmt.Errorf("LLM response is not valid JSON: %w Raw: %s", err, string(rawBytes))
	}

	obj["security"] = secCtx
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(obj); err != nil {
		return fmt.Errorf("encode output: %w", err)
	}
	return nil
}

// Markdownの装飾を取り除くヘルパー関数
func cleanLLMOutput(content string) string {
	content = strings.TrimSpace(content)
	// ```json または ``` で始まる場合、それを削除
	if strings.HasPrefix(content, "```") {
		lines := strings.Split(content, "\n")
		if len(lines) >= 2 {
			// 最初の行（```json）と最後の行（```）を削除
			// ただし中身が壊れないように慎重に処理
			var newLines []string
			for i, line := range lines {
				if i == 0 && strings.HasPrefix(line, "```") {
					continue
				}
				if i == len(lines)-1 && strings.HasPrefix(line, "```") {
					continue
				}
				newLines = append(newLines, line)
			}
			return strings.Join(newLines, "\n")
		}
	}
	return content
}

func chooseModel(flagVal, def string) string {
	if strings.TrimSpace(flagVal) != "" {
		return strings.TrimSpace(flagVal)
	}
	return def
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

func exitErr(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(2)
}
