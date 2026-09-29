package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Bridge struct {
		URL       string `yaml:"url"`
		AuthToken string `yaml:"authToken"`
		// E2EKey is a second secret shared ONLY between adapter and helpers
		// (never given to the cloud function). When set, stream payloads are
		// encrypted end-to-end so neither the cloud function nor the cloud
		// provider can read or forge them. Strongly recommended.
		E2EKey    string `yaml:"e2eKey"`
		Reconnect struct {
			InitialDelayMs    int     `yaml:"initialDelayMs"`
			MaxDelayMs        int     `yaml:"maxDelayMs"`
			BackoffMultiplier float64 `yaml:"backoffMultiplier"`
		} `yaml:"reconnect"`
		PingIntervalMs int `yaml:"pingIntervalMs"`
	} `yaml:"bridge"`
	Target struct {
		Address string `yaml:"address"`
	} `yaml:"target"`
	HTTP struct {
		ListenPort int    `yaml:"listenPort"`
		Path       string `yaml:"path"`
	} `yaml:"http"`
	Listen struct {
		Address string `yaml:"address"`
	} `yaml:"listen"`
	WsAPI struct {
		Mode  string `yaml:"mode"`
		Relay bool   `yaml:"relay"`
	} `yaml:"wsApi"`
	WriteCoalescing struct {
		Enabled bool `yaml:"enabled"`
		DelayMs int  `yaml:"delayMs"`
	} `yaml:"writeCoalescing"`
	Logging struct {
		Level string `yaml:"level"`
	} `yaml:"logging"`
}

func (c *Config) InitialDelay() time.Duration {
	return time.Duration(c.Bridge.Reconnect.InitialDelayMs) * time.Millisecond
}

func (c *Config) MaxDelay() time.Duration {
	return time.Duration(c.Bridge.Reconnect.MaxDelayMs) * time.Millisecond
}

func (c *Config) PingInterval() time.Duration {
	return time.Duration(c.Bridge.PingIntervalMs) * time.Millisecond
}

func (c *Config) CoalesceDelay() time.Duration {
	if !c.WriteCoalescing.Enabled || c.WriteCoalescing.DelayMs <= 0 {
		return 0
	}
	return time.Duration(c.WriteCoalescing.DelayMs) * time.Millisecond
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// MinSecretLen is the minimum accepted length for authToken / e2eKey.
const MinSecretLen = 16

// Validate checks security-relevant settings and fills in safe defaults for
// missing optional values. role is "adapter" or "helper". It returns
// non-fatal warnings for the caller to log.
func (c *Config) Validate(role string) (warnings []string, err error) {
	c.Bridge.AuthToken = strings.TrimSpace(c.Bridge.AuthToken)
	c.Bridge.E2EKey = strings.TrimSpace(c.Bridge.E2EKey)

	if len(c.Bridge.AuthToken) < MinSecretLen {
		return nil, fmt.Errorf("bridge.authToken must be at least %d characters (use e.g. `openssl rand -hex 32`)", MinSecretLen)
	}
	if c.Bridge.E2EKey != "" {
		if len(c.Bridge.E2EKey) < MinSecretLen {
			return nil, fmt.Errorf("bridge.e2eKey must be at least %d characters (use e.g. `openssl rand -hex 32`)", MinSecretLen)
		}
		if c.Bridge.E2EKey == c.Bridge.AuthToken {
			return nil, errors.New("bridge.e2eKey must differ from bridge.authToken (the cloud function knows authToken)")
		}
	} else {
		warnings = append(warnings, "bridge.e2eKey is not set: stream data is authenticated, but the cloud function (and thus the cloud provider) could decrypt it. Set the same e2eKey on the adapter and every helper.")
	}
	u, err := url.Parse(c.Bridge.URL)
	if err != nil {
		return nil, fmt.Errorf("bridge.url: %w", err)
	}
	// Plain ws:// is only allowed to a loopback host (local testing).
	if u.Scheme != "wss" && !(u.Scheme == "ws" && isLoopbackHost(u.Hostname())) {
		return nil, errors.New("bridge.url must start with wss://")
	}

	// Reconnect/backoff defaults: a zero multiplier or delay would turn the
	// reconnect loop into a busy loop hammering the API Gateway.
	r := &c.Bridge.Reconnect
	if r.InitialDelayMs <= 0 {
		r.InitialDelayMs = 1000
	}
	if r.MaxDelayMs < r.InitialDelayMs {
		r.MaxDelayMs = 30000
		if r.MaxDelayMs < r.InitialDelayMs {
			r.MaxDelayMs = r.InitialDelayMs
		}
	}
	if r.BackoffMultiplier < 1 {
		r.BackoffMultiplier = 2
	}
	if c.Bridge.PingIntervalMs <= 0 {
		// PING/PONG refreshes the IAM token and keeps the WS from idling out.
		c.Bridge.PingIntervalMs = 30000
	}

	switch role {
	case "adapter":
		if c.Target.Address == "" {
			return nil, errors.New("target.address is required")
		}
		if c.HTTP.ListenPort <= 0 || c.HTTP.ListenPort > 65535 {
			return nil, errors.New("http.listenPort must be 1..65535 (the cloud function needs the recovery endpoint)")
		}
		if c.HTTP.Path == "" || c.HTTP.Path == "/conn-ids" {
			warnings = append(warnings, "http.path is the default /conn-ids; consider a random path")
		}
	case "helper":
		if c.Listen.Address == "" {
			return nil, errors.New("listen.address is required")
		}
		host, _, err := net.SplitHostPort(c.Listen.Address)
		if err != nil {
			return nil, fmt.Errorf("listen.address: %w", err)
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			warnings = append(warnings, "listen.address is not a loopback address: anyone who can reach it can use your tunnel")
		}
	}
	return warnings, nil
}
