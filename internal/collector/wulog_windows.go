//go:build windows

package collector

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"winopsguard/internal/model"
)

// CollectWULog executes Get-WindowsUpdateLog and falls back to existing file.
func CollectWULog(tempDir string, maxBytes int64) (model.WULog, error) {
	out := model.WULog{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if tempDir == "" {
		tempDir = os.TempDir()
	}
	tmpFile := filepath.Join(tempDir, fmt.Sprintf("winopsguard-wu-%d.log", time.Now().Unix()))

	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf(`Get-WindowsUpdateLog -LogPath '%s'`, tmpFile))
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	if err := cmd.Run(); err == nil {
		data, err := readLimited(tmpFile, maxBytes)
		if err == nil {
			out.Summary, out.Excerpt = summarizeWULog(data)
			_ = os.Remove(tmpFile)
			return out, nil
		}
	}

	fallback := `C:\Windows\WindowsUpdate.log`
	data, err := readLimited(fallback, maxBytes)
	if err != nil {
		return out, fmt.Errorf("windows update log unavailable: %w", err)
	}
	out.Summary, out.Excerpt = summarizeWULog(data)
	return out, nil
}

func readLimited(path string, max int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if max <= 0 {
		max = 5 * 1024 * 1024
	}
	lim := io.LimitedReader{R: f, N: max}
	b, err := io.ReadAll(&lim)
	return string(b), err
}

func summarizeWULog(content string) (string, []string) {
	lines := bytes.Split([]byte(content), []byte("\n"))
	var excerpt []string
	for i, line := range lines {
		if len(excerpt) >= 5 {
			break
		}
		if bytes.Contains(line, []byte("Error")) || bytes.Contains(line, []byte("0x")) {
			excerpt = append(excerpt, string(bytes.TrimSpace(line)))
		}
		// also take last line for context
		if i == len(lines)-1 && len(line) > 0 {
			excerpt = append(excerpt, string(bytes.TrimSpace(line)))
		}
	}
	summary := "Windows Update log collected"
	if len(excerpt) == 0 {
		excerpt = append(excerpt, "")
	}
	return summary, excerpt
}
