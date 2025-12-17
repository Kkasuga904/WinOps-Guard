package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"winopsguard/internal/config"
	"winopsguard/internal/logging"
	"winopsguard/internal/model"
	"winopsguard/internal/store"
)

type Client struct {
	http *http.Client
	cfg  config.Config
}

// NewClient builds HTTP client honoring proxy env.
func NewClient(cfg config.Config) *Client {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &Client{
		http: &http.Client{Transport: tr, Timeout: 30 * time.Second},
		cfg:  cfg,
	}
}

// BuildRequest constructs AI payload.
func BuildRequest(cfg config.Config, sys, app model.LogSet, wu model.WULog) (model.AIRequest, error) {
	req := model.AIRequest{}
	host := cfg.Hostname
	if host == "" {
		h, err := os.Hostname()
		if err == nil {
			host = h
		}
	}
	osVersion := cfg.OSVersion
	req.Host.Hostname = host
	req.Host.OS = osVersion
	req.TimestampUTC = time.Now().UTC().Format(time.RFC3339)
	req.Collection.WindowMinutes = cfg.CollectionWindowMinute
	req.Collection.MaxEvents = cfg.MaxEvents
	req.EventLog.System = sys
	req.EventLog.Application = app
	req.WindowsUpdateLog = wu
	req.Ask = "Identify likely causes and propose investigative PowerShell commands. Do not execute."
	return req, nil
}

// SendWithRetry posts request; failure leaves queue entry intact.
func (c *Client) SendWithRetry(req *store.Request, q *store.Queue, maxRetry int) {
	data, err := json.Marshal(req.Payload)
	if err != nil {
		logging.Logger.Printf("marshal request failed: %v", err)
		return
	}
	for i := 0; i <= maxRetry; i++ {
		if err := c.doSend(data); err != nil {
			backoff := time.Duration(1<<i) * time.Second
			logging.Logger.Printf("send attempt %d failed: %v; retry in %s", i+1, err, backoff)
			time.Sleep(backoff)
			continue
		}
		q.MarkSent(req.ID)
		logging.Logger.Printf("request %s delivered", req.ID)
		return
	}
}

func (c *Client) doSend(body []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.APIURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	token := os.Getenv("WINOPSGUARD_API_TOKEN")
	if token == "" {
		token = c.cfg.APIToken
	}
	if token == "" {
		return errors.New("api token missing")
	}
	hreq.Header.Set("Authorization", "Bearer "+token)
	hreq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(hreq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("server error %d", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("client error %d", resp.StatusCode)
	}
	return nil
}

// ValidateResponse ensures no destructive commands are proposed.
func ValidateResponse(res model.AIResponse) error {
	for _, cmd := range res.RecommendedCommands {
		if containsDanger(cmd.Command) {
			return fmt.Errorf("dangerous command detected: %s", cmd.Command)
		}
	}
	return nil
}

func containsDanger(cmd string) bool {
	dangerTokens := []string{
		"stop-service", "restart-service", "sc stop", "shutdown", "format", "delete", "remove-item", "del ", "rm ",
	}
	lc := strings.ToLower(cmd)
	for _, t := range dangerTokens {
		if strings.Contains(lc, t) {
			return true
		}
	}
	return false
}
