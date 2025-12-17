//go:build windows

package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"winopsguard/internal/model"
	"winopsguard/internal/summarizer"
)

// CollectEventLogs returns summarized System and Application logs.
func CollectEventLogs(window time.Duration, maxEvents int) (model.LogSet, model.LogSet, error) {
	sysEvents, err := readViaWevtapi("System", window, maxEvents)
	if err != nil {
		sysEvents, err = readViaPS("System", window, maxEvents)
		if err != nil {
			return model.LogSet{}, model.LogSet{}, fmt.Errorf("system log: %w", err)
		}
	}

	appEvents, err := readViaWevtapi("Application", window, maxEvents)
	if err != nil {
		appEvents, err = readViaPS("Application", window, maxEvents)
		if err != nil {
			return model.LogSet{}, model.LogSet{}, fmt.Errorf("application log: %w", err)
		}
	}

	sysLog := summarizer.SummarizeEvents(summarizer.TrimWhitespace(sysEvents), maxEvents)
	appLog := summarizer.SummarizeEvents(summarizer.TrimWhitespace(appEvents), maxEvents)
	return sysLog, appLog, nil
}

// readViaWevtapi is a placeholder for direct wevtapi.dll access.
func readViaWevtapi(logName string, window time.Duration, max int) ([]model.Event, error) {
	return nil, errors.New("wevtapi path not implemented; falling back to powershell")
}

func readViaPS(logName string, window time.Duration, max int) ([]model.Event, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	minutes := int(window.Minutes())
	if minutes == 0 {
		minutes = 1
	}

	script := fmt.Sprintf(`
$dt = (Get-Date).ToUniversalTime().AddMinutes(-%d)
Get-WinEvent -LogName '%s' -MaxEvents %d |
 Where-Object { $_.TimeCreated -ge $dt } |
 Select-Object @{Name="time";Expression={$_.TimeCreated.ToUniversalTime()}},
               @{Name="level";Expression={$_.LevelDisplayName}},
               @{Name="event_id";Expression={$_.Id}},
               @{Name="source";Expression={$_.ProviderName}},
               @{Name="message";Expression={$_.Message}} |
 ConvertTo-Json -Compress -Depth 4
`, minutes, logName, max)

	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("powershell Get-WinEvent: %w output=%s", err, out.String())
	}

	data := out.Bytes()
	// PowerShell returns either object or array; normalize to array.
	if len(data) == 0 {
		return []model.Event{}, nil
	}
	if data[0] == '{' {
		data = append([]byte("["), data...)
		data = append(data, ']')
	}

	var evs []model.Event
	if err := json.Unmarshal(data, &evs); err != nil {
		return nil, err
	}
	if len(evs) > max {
		evs = evs[:max]
	}
	return evs, nil
}
