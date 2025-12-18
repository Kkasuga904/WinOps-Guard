package main

import (
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	evtQueryChannelPath              = 0x1
	evtQueryTolerateQueryErrs        = 0x1000
	evtRenderEventXML                = 1
	evtFormatMessageEvent            = 1
	defaultLookbackMinutes           = 10
	defaultMaxEvents                 = 256
	defaultLogName                   = "application"
	evtNextBatchSize          uint32 = 16
)

var (
	modWevtapi                   = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery                 = modWevtapi.NewProc("EvtQuery")
	procEvtNext                  = modWevtapi.NewProc("EvtNext")
	procEvtRender                = modWevtapi.NewProc("EvtRender")
	procEvtClose                 = modWevtapi.NewProc("EvtClose")
	procEvtOpenPublisherMetadata = modWevtapi.NewProc("EvtOpenPublisherMetadata")
	procEvtFormatMessage         = modWevtapi.NewProc("EvtFormatMessage")
)

type eventRecord struct {
	TimeGenerated time.Time `json:"timeGenerated"`
	Level         string    `json:"level"`
	EventID       uint32    `json:"eventId"`
	Source        string    `json:"source"`
	Message       string    `json:"message"`
}

type eventXML struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     uint32 `xml:"EventID"`
		Level       uint32 `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
}

type publisherCache struct {
	mu      sync.Mutex
	handles map[string]windows.Handle
}

func (c *publisherCache) get(provider string) (windows.Handle, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.handles == nil {
		c.handles = make(map[string]windows.Handle)
	}
	if h, ok := c.handles[provider]; ok {
		return h, nil
	}
	ptr, err := windows.UTF16PtrFromString(provider)
	if err != nil {
		return 0, fmt.Errorf("publisher UTF16: %w", err)
	}
	r, _, callErr := procEvtOpenPublisherMetadata.Call(
		0, // local session
		uintptr(unsafe.Pointer(ptr)),
		0, // log file path
		0, // locale
		0, // flags
	)
	if r == 0 {
		return 0, fmt.Errorf("EvtOpenPublisherMetadata: %w", callErr)
	}
	h := windows.Handle(r)
	c.handles[provider] = h
	return h, nil
}

func (c *publisherCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, h := range c.handles {
		evtCloseHandle(h)
		delete(c.handles, k)
	}
}

func main() {
	minutes := flag.Int("minutes", defaultLookbackMinutes, "lookback window in minutes")
	maxEvents := flag.Int("max", defaultMaxEvents, "maximum number of events to return")
	logName := flag.String("log", defaultLogName, "event log channel: application|system|setup")
	provider := flag.String("provider", "", "optional provider name filter (e.g. Microsoft-Windows-WindowsUpdateClient)")
	flag.Parse()

	channel, err := normalizeLogName(*logName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	events, err := fetchEvents(channel, strings.TrimSpace(*provider), *minutes, *maxEvents)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(events); err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode JSON: %v\n", err)
		os.Exit(2)
	}
}

func normalizeLogName(name string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "application", "":
		return "Application", nil
	case "system":
		return "System", nil
	case "setup":
		return "Setup", nil
	default:
		return "", fmt.Errorf("unsupported log: %s (use application|system|setup)", name)
	}
}

func fetchEvents(logName, provider string, minutes, maxEvents int) ([]eventRecord, error) {
	if minutes <= 0 {
		minutes = defaultLookbackMinutes
	}
	if maxEvents <= 0 {
		maxEvents = defaultMaxEvents
	}

	ms := minutes * 60 * 1000
	queryStr := buildQuery(ms, provider)
	queryPtr, err := windows.UTF16PtrFromString(queryStr)
	if err != nil {
		return nil, fmt.Errorf("query UTF16: %w", err)
	}
	pathPtr, err := windows.UTF16PtrFromString(logName)
	if err != nil {
		return nil, fmt.Errorf("path UTF16: %w", err)
	}

	hQuery, err := evtQuery(pathPtr, queryPtr)
	if err != nil {
		return nil, err
	}
	defer evtCloseHandle(hQuery)

	var (
		results = make([]eventRecord, 0, maxEvents)
		cache   publisherCache
	)
	defer cache.close()

	for len(results) < maxEvents {
		handles, err := evtNextBatch(hQuery, evtNextBatchSize)
		if err != nil {
			if err == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			return nil, err
		}
		for _, hEvt := range handles {
			rec, err := parseEvent(hEvt, &cache)
			evtCloseHandle(hEvt)
			if err != nil {
				return nil, err
			}
			results = append(results, rec)
			if len(results) >= maxEvents {
				break
			}
		}
	}
	return results, nil
}

func buildQuery(ms int, provider string) string {
	if provider == "" {
		return fmt.Sprintf("*[System[TimeCreated[timediff(@SystemTime) <= %d]]]", ms)
	}
	quotedProvider := strconv.Quote(provider)
	return fmt.Sprintf("*[System[Provider[@Name=%s] and TimeCreated[timediff(@SystemTime) <= %d]]]", quotedProvider, ms)
}

func evtQuery(path, query *uint16) (windows.Handle, error) {
	r, _, err := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(path)),
		uintptr(unsafe.Pointer(query)),
		evtQueryChannelPath|evtQueryTolerateQueryErrs,
	)
	if r == 0 {
		return 0, fmt.Errorf("EvtQuery: %w", err)
	}
	return windows.Handle(r), nil
}

func evtNextBatch(hQuery windows.Handle, batch uint32) ([]windows.Handle, error) {
	handles := make([]windows.Handle, batch)
	var returned uint32
	r, _, err := procEvtNext.Call(
		uintptr(hQuery),
		uintptr(batch),
		uintptr(unsafe.Pointer(&handles[0])),
		2000, // 2s timeout
		0,
		uintptr(unsafe.Pointer(&returned)),
	)
	if r == 0 {
		if errno, ok := err.(windows.Errno); ok && errno == windows.ERROR_NO_MORE_ITEMS {
			return nil, windows.ERROR_NO_MORE_ITEMS
		}
		return nil, fmt.Errorf("EvtNext: %w", err)
	}
	return handles[:returned], nil
}

func parseEvent(hEvt windows.Handle, cache *publisherCache) (eventRecord, error) {
	xmlText, err := renderEventXML(hEvt)
	if err != nil {
		return eventRecord{}, err
	}
	var parsed eventXML
	if err := xml.Unmarshal([]byte(xmlText), &parsed); err != nil {
		return eventRecord{}, fmt.Errorf("parse XML: %w", err)
	}

	timestamp, err := time.Parse(time.RFC3339Nano, parsed.System.TimeCreated.SystemTime)
	if err != nil {
		return eventRecord{}, fmt.Errorf("parse time: %w", err)
	}

	levelText := mapLevel(parsed.System.Level)
	source := parsed.System.Provider.Name

	meta, err := cache.get(source)
	if err != nil {
		return eventRecord{}, err
	}

	msg, err := formatMessage(meta, hEvt)
	if err != nil {
		return eventRecord{}, err
	}

	return eventRecord{
		TimeGenerated: timestamp.UTC(),
		Level:         levelText,
		EventID:       parsed.System.EventID,
		Source:        source,
		Message:       msg,
	}, nil
}

func renderEventXML(hEvt windows.Handle) (string, error) {
	var bufferUsed uint32
	var propCount uint32

	r, _, err := procEvtRender.Call(
		0,
		uintptr(hEvt),
		evtRenderEventXML,
		0,
		0,
		uintptr(unsafe.Pointer(&bufferUsed)),
		uintptr(unsafe.Pointer(&propCount)),
	)
	if r == 0 {
		if errno, ok := err.(windows.Errno); !ok || errno != windows.ERROR_INSUFFICIENT_BUFFER {
			return "", fmt.Errorf("EvtRender(size): %w", err)
		}
	}

	buffer := make([]uint16, bufferUsed)
	r, _, err = procEvtRender.Call(
		0,
		uintptr(hEvt),
		evtRenderEventXML,
		uintptr(bufferUsed),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&bufferUsed)),
		uintptr(unsafe.Pointer(&propCount)),
	)
	if r == 0 {
		return "", fmt.Errorf("EvtRender: %w", err)
	}

	return windows.UTF16ToString(buffer), nil
}

func formatMessage(meta windows.Handle, hEvt windows.Handle) (string, error) {
	var used uint32
	r, _, err := procEvtFormatMessage.Call(
		uintptr(meta),
		uintptr(hEvt),
		0,
		0,
		0,
		evtFormatMessageEvent,
		0,
		0,
		uintptr(unsafe.Pointer(&used)),
	)
	if r == 0 {
		if errno, ok := err.(windows.Errno); !ok || errno != windows.ERROR_INSUFFICIENT_BUFFER {
			return "", fmt.Errorf("EvtFormatMessage(size): %w", err)
		}
	}

	buf := make([]uint16, used)
	r, _, err = procEvtFormatMessage.Call(
		uintptr(meta),
		uintptr(hEvt),
		0,
		0,
		0,
		evtFormatMessageEvent,
		uintptr(used),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&used)),
	)
	if r == 0 {
		return "", fmt.Errorf("EvtFormatMessage: %w", err)
	}
	return strings.TrimSpace(windows.UTF16ToString(buf)), nil
}

func mapLevel(level uint32) string {
	switch level {
	case 2:
		return "Error"
	case 3:
		return "Warning"
	case 4:
		return "Information"
	default:
		return "Unknown"
	}
}

func evtCloseHandle(h windows.Handle) {
	if h == 0 {
		return
	}
	procEvtClose.Call(uintptr(h))
}
