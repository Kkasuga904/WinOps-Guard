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
	defaultProvider = "openai"
	defaultOpenAIModel = "gpt-4o-mini"
	defaultGeminiModel = "gemini-1.5-flash"
	defaultTimeout = 30 * time.Second
	defaultMaxBytes = 5_000_000
	openAIEndpoint = "https://api.openai.com/v1/chat/completions"
	geminiEndpointFmt = "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s"
	maxOutputTokens = 1200
)

const systemPrompt = `You are an SRE-grade Windows operations triage engine.
You MUST output valid JSON that strictly follows the schema below.
Do NOT include explanations, markdown, or extra text.
If you are unsure, return a low-confidence result with no actions.
You are NOT allowed to invent commands.
You must be conservative and risk-averse.`

const userPromptTemplate = `Input is a JSON array of Windows Event Log entries.
Each entry has: timeGenerated, level, eventId, source, message.

Your task:
1. Identify whether these events indicate a real operational problem.
2. Classify the situation (noise / installer / windows_update / service / unknown).
3. Decide whether ANY action is safe to recommend.
4. Output ONLY the JSON object that follows the required schema.

Constraints:
- Prefer "no action" unless there is clear evidence of failure.
- Do NOT suggest reboot, disk operations, registry edits, or destructive commands.
- Windows Update failures must be clearly identified by source or error codes.

REQUIRED OUTPUT SCHEMA (must be valid JSON):
{
  "summary": string,
  "severity": "info" | "warning" | "critical",
  "confidence": number,
  "classification": string,
  "signals": [{"type":"event","source":string,"id":number}],
  "actions": [{
    "id": string,
    "title": string,
    "risk": "none" | "low" | "medium" | "high",
    "commands": [{"shell":"powershell","cmd":string}]
  }]
}

EVENTS_JSON:
%s`

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

	normalizedInput, err := ensureJSONArray(rawInput)
	if err != nil {
		exitErr(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	res, err := dispatchLLM(ctx, *provider, *model, normalizedInput)
	if err != nil {
		exitErr(err)
	}

	if err := outputFormattedJSON(res); err != nil {
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
	return buf, nil
}

func ensureJSONArray(raw []byte) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		trimmed = []byte("[]")
	}

	var arr []json.RawMessage
	if err := json.Unmarshal(trimmed, &arr); err != nil {
		return "", fmt.Errorf("stdin must be a JSON array: %w", err)
	}
	return string(trimmed), nil
}

func dispatchLLM(ctx context.Context, provider, model, eventsJSON string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(provider))
	switch p {
	case "openai", "":
		return callOpenAI(ctx, chooseModel(model, defaultOpenAIModel), eventsJSON)
	case "gemini":
		return callGemini(ctx, chooseModel(model, defaultGeminiModel), eventsJSON)
	default:
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}
}

func callOpenAI(ctx context.Context, model, eventsJSON string) (string, error) {
	apiKey := strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
	if apiKey == "" {
		return "", errors.New("OPENAI_API_KEY is not set")
	}

	userPrompt := fmt.Sprintf(userPromptTemplate, eventsJSON)
	reqBody := struct {
		Model       string `json:"model"`
		Temperature float64 `json:"temperature"`
		MaxTokens   int    `json:"max_tokens,omitempty"`
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

func callGemini(ctx context.Context, model, eventsJSON string) (string, error) {
	apiKey := strings.TrimSpace(os.Getenv("GEMINI_API_KEY"))
	if apiKey == "" {
		return "", errors.New("GEMINI_API_KEY is not set")
	}

	userPrompt := fmt.Sprintf(userPromptTemplate, eventsJSON)
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
			Temperature float64 `json:"temperature,omitempty"`
			MaxOutputTokens int `json:"maxOutputTokens,omitempty"`
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

func outputFormattedJSON(raw string) error {
	rawBytes := bytes.TrimSpace([]byte(raw))
	if len(rawBytes) == 0 {
		return errors.New("LLM response is empty")
	}

	var tmp json.RawMessage
	if err := json.Unmarshal(rawBytes, &tmp); err != nil {
		return fmt.Errorf("LLM response is not valid JSON: %w", err)
	}

	var buf bytes.Buffer
	if err := json.Indent(&buf, rawBytes, "", "  "); err != nil {
		return fmt.Errorf("format JSON: %w", err)
	}
	_, err := buf.WriteTo(os.Stdout)
	return err
}

func chooseModel(flagVal, def string) string {
	if strings.TrimSpace(flagVal) != "" {
		return strings.TrimSpace(flagVal)
	}
	return def
}

func exitErr(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
