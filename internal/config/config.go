package config

import (
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"time"
)

// Config holds runtime configuration. Environment variables override file values.
type Config struct {
	APIURL                 string `json:"api_url"`
	APIToken               string `json:"api_token"`
	CollectionWindowMinute int    `json:"collection_window_minutes"`
	MaxEvents              int    `json:"max_events"`
	MaxSendBytes           int64  `json:"max_send_bytes"`
	MaxLogBytes            int64  `json:"max_log_bytes"`
	WULogTempPath          string `json:"wu_log_temp_path"`
	QueueDir               string `json:"queue_dir"`
	Hostname               string `json:"hostname"`
	OSVersion              string `json:"os_version"`
}

// Load reads config.json then applies environment overrides.
func Load(path string) (Config, error) {
	cfg := defaultConfig()

	if _, err := os.Stat(path); err == nil {
		b, err := os.ReadFile(path)
		if err != nil {
			return cfg, err
		}
		if err := json.Unmarshal(b, &cfg); err != nil {
			return cfg, err
		}
	}

	applyEnv(&cfg)
	if cfg.APIURL == "" {
		return cfg, errors.New("api_url is required")
	}
	if cfg.APIToken == "" {
		return cfg, errors.New("api_token is required")
	}
	return cfg, nil
}

// Window returns collection window duration.
func (c Config) Window() time.Duration {
	return time.Duration(c.CollectionWindowMinute) * time.Minute
}

func defaultConfig() Config {
	return Config{
		APIURL:                 "",
		APIToken:               "",
		CollectionWindowMinute: 60,
		MaxEvents:              200,
		MaxSendBytes:           512 * 1024,
		MaxLogBytes:            5 * 1024 * 1024,
		WULogTempPath:          os.TempDir(),
		QueueDir:               "queue",
		Hostname:               "",
		OSVersion:              "",
	}
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("WINOPSGUARD_API_URL"); v != "" {
		cfg.APIURL = v
	}
	if v := os.Getenv("WINOPSGUARD_API_TOKEN"); v != "" {
		cfg.APIToken = v
	}
	if v := os.Getenv("WINOPSGUARD_COLLECTION_WINDOW_MINUTES"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.CollectionWindowMinute = i
		}
	}
	if v := os.Getenv("WINOPSGUARD_MAX_EVENTS"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.MaxEvents = i
		}
	}
	if v := os.Getenv("WINOPSGUARD_MAX_SEND_BYTES"); v != "" {
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			cfg.MaxSendBytes = i
		}
	}
	if v := os.Getenv("WINOPSGUARD_MAX_LOG_BYTES"); v != "" {
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			cfg.MaxLogBytes = i
		}
	}
	if v := os.Getenv("WINOPSGUARD_WULOG_TEMP_PATH"); v != "" {
		cfg.WULogTempPath = v
	}
	if v := os.Getenv("WINOPSGUARD_QUEUE_DIR"); v != "" {
		cfg.QueueDir = v
	}
	if v := os.Getenv("WINOPSGUARD_HOSTNAME"); v != "" {
		cfg.Hostname = v
	}
	if v := os.Getenv("WINOPSGUARD_OS_VERSION"); v != "" {
		cfg.OSVersion = v
	}
}
