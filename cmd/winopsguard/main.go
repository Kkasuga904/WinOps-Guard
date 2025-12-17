package main

import (
	"log"
	"os"
	"time"

	"winopsguard/internal/api"
	"winopsguard/internal/collector"
	"winopsguard/internal/config"
	"winopsguard/internal/logging"
	"winopsguard/internal/sanitizer"
	"winopsguard/internal/store"
	"winopsguard/internal/summarizer"
)

func main() {
	cfg, err := config.Load("config.json")
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}

	sysLog, appLog, err := collector.CollectEventLogs(cfg.Window(), cfg.MaxEvents)
	if err != nil {
		logging.Logger.Fatalf("collect event logs: %v", err)
	}

	wu, err := collector.CollectWULog(cfg.WULogTempPath, cfg.MaxLogBytes)
	if err != nil {
		logging.Logger.Printf("collect windows update log warning: %v", err)
	}

	req := summarizer.BuildPayload(sysLog, appLog, wu, cfg.MaxSendBytes)
	req.Collection.WindowMinutes = cfg.CollectionWindowMinute
	req.Collection.MaxEvents = cfg.MaxEvents
	req.TimestampUTC = time.Now().UTC().Format(time.RFC3339)

	host := cfg.Hostname
	if host == "" {
		h, _ := os.Hostname()
		host = h
	}
	req.Host.Hostname = host
	req.Host.OS = cfg.OSVersion

	sanitizer.MaskRequest(&req)

	q := store.NewQueue(cfg.QueueDir)
	queueReq := q.Enqueue(req)

	client := api.NewClient(cfg)
	go client.SendWithRetry(queueReq, q, 3)

	logging.Logger.Printf("request %s queued", queueReq.ID)
}
