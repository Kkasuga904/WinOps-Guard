package model

import "time"

// Event represents a Windows event log entry after normalization.
type Event struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	EventID uint32    `json:"event_id"`
	Source  string    `json:"source"`
	Message string    `json:"message"`
}

type TopEventID struct {
	ID    uint32 `json:"id"`
	Count int    `json:"count"`
}

// LogSet stores summarized information per log channel.
type LogSet struct {
	LevelCounts map[string]int `json:"level_counts"`
	TopEventIDs []TopEventID   `json:"top_event_ids"`
	Recent      []Event        `json:"recent"`
	Raw         []Event        `json:"-"`
}

// WULog holds Windows Update log excerpts.
type WULog struct {
	Summary string   `json:"summary"`
	Excerpt []string `json:"excerpt"`
}

// AIRequest is the payload sent to LLM.
type AIRequest struct {
	Host struct {
		Hostname string `json:"hostname"`
		OS       string `json:"os_version"`
	} `json:"host"`
	TimestampUTC string `json:"ts_utc"`
	Collection   struct {
		WindowMinutes int `json:"window_minutes"`
		MaxEvents     int `json:"max_events"`
	} `json:"collection"`
	EventLog struct {
		System      LogSet `json:"system"`
		Application LogSet `json:"application"`
	} `json:"eventlog"`
	WindowsUpdateLog WULog  `json:"windows_update_log"`
	Ask             string `json:"ask"`
}

// AIResponse defines fixed structure expected from LLM.
type AIResponse struct {
	Status                  string `json:"status"`
	LikelyCauses            []Cause `json:"likely_causes"`
	RecommendedCommands     []Command `json:"recommended_commands"`
	Warnings                []string `json:"warnings"`
	Uncertainties           []string `json:"uncertainties"`
	AdditionalLogsRequested []string `json:"additional_logs_requested"`
}

type Cause struct {
	Title     string   `json:"title"`
	Evidence  []string `json:"evidence"`
	Confidence string  `json:"confidence"`
	Notes     string   `json:"notes"`
}

type Command struct {
	Command string `json:"command"`
	Purpose string `json:"purpose"`
	Risk    string `json:"risk"`
}
