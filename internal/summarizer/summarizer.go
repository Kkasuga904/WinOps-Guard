package summarizer

import (
	"encoding/json"
	"sort"
	"strings"

	"winopsguard/internal/model"
)

// SummarizeEvents builds counts and top IDs from raw events.
func SummarizeEvents(events []model.Event, maxRecent int) model.LogSet {
	levelCounts := map[string]int{}
	idCounts := map[uint32]int{}
	var recent []model.Event

	for _, ev := range events {
		levelCounts[ev.Level]++
		idCounts[ev.EventID]++
	}

	if len(events) > maxRecent {
		recent = append(recent, events[:maxRecent]...)
	} else {
		recent = append(recent, events...)
	}

	topIDs := make([]model.TopEventID, 0, len(idCounts))
	for id, c := range idCounts {
		topIDs = append(topIDs, model.TopEventID{ID: id, Count: c})
	}
	sort.Slice(topIDs, func(i, j int) bool {
		if topIDs[i].Count == topIDs[j].Count {
			return topIDs[i].ID < topIDs[j].ID
		}
		return topIDs[i].Count > topIDs[j].Count
	})
	if len(topIDs) > 5 {
		topIDs = topIDs[:5]
	}

	return model.LogSet{
		LevelCounts: levelCounts,
		TopEventIDs: topIDs,
		Recent:      recent,
		Raw:         events,
	}
}

// BuildPayload trims payload to fit within size budget.
func BuildPayload(sys model.LogSet, app model.LogSet, wu model.WULog, maxBytes int64) model.AIRequest {
	req := model.AIRequest{}
	req.EventLog.System = sys
	req.EventLog.Application = app
	req.WindowsUpdateLog = wu
	req.Collection.MaxEvents = len(sys.Raw) + len(app.Raw)
	req.Ask = "Identify likely causes and propose investigative PowerShell commands. Do not execute."
	req.Collection.WindowMinutes = 0 // caller must set
	trimToSize(&req, maxBytes)
	return req
}

func trimToSize(req *model.AIRequest, maxBytes int64) {
	recentLimit := 50
	messageLimit := 512

	for {
		b, _ := json.Marshal(req)
		if int64(len(b)) <= maxBytes || (recentLimit == 0 && messageLimit == 64) {
			return
		}
		// Reduce message size first
		for i := range req.EventLog.System.Recent {
			req.EventLog.System.Recent[i].Message = truncate(req.EventLog.System.Recent[i].Message, messageLimit)
		}
		for i := range req.EventLog.Application.Recent {
			req.EventLog.Application.Recent[i].Message = truncate(req.EventLog.Application.Recent[i].Message, messageLimit)
		}
		// Reduce number of recents
		if len(req.EventLog.System.Recent) > recentLimit {
			req.EventLog.System.Recent = req.EventLog.System.Recent[:recentLimit]
		}
		if len(req.EventLog.Application.Recent) > recentLimit {
			req.EventLog.Application.Recent = req.EventLog.Application.Recent[:recentLimit]
		}
		// tighten limits for next loop
		if recentLimit > 10 {
			recentLimit -= 10
		} else {
			recentLimit = 0
		}
		if messageLimit > 128 {
			messageLimit /= 2
		} else {
			messageLimit = 64
		}
	}
}

func truncate(s string, limit int) string {
	if limit <= 0 || len(s) <= limit {
		return s
	}
	return s[:limit] + "...(truncated)"
}

// MaskStrings applies in-place string masking helper.
func MaskStrings(entries []string, mask func(string) string) []string {
	out := make([]string, len(entries))
	for i, s := range entries {
		out[i] = mask(s)
	}
	return out
}

// TrimWhitespace normalizes whitespace in messages.
func TrimWhitespace(events []model.Event) []model.Event {
	for i := range events {
		events[i].Message = strings.TrimSpace(events[i].Message)
	}
	return events
}
