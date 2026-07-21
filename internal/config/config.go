package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"digitdojo-shield/internal/firewall/backend"
)

type Config struct {
	General   GeneralConfig   `yaml:"general"`
	Firewall  FirewallConfig  `yaml:"firewall"`
	Detection DetectionConfig `yaml:"detection"`
	Alerts    AlertsConfig    `yaml:"alerts"`
	Logging   LoggingConfig   `yaml:"logging"`
	API       APIConfig       `yaml:"api"`
}

type GeneralConfig struct {
	LogDir    string `yaml:"log_dir"`
	StateDir  string `yaml:"state_dir"`
	HostBased bool   `yaml:"host_based"`
}

type FirewallConfig struct {
	Backend             string `yaml:"backend"`
	RateLimitPerSecond  int    `yaml:"rate_limit_per_second"`
	ConnectionLimit     int    `yaml:"connection_limit"`
	TemporaryBanSeconds int    `yaml:"temporary_ban_seconds"`
}

type DetectionConfig struct {
	PacketThreshold     int `yaml:"packet_threshold"`
	ConnectionThreshold int `yaml:"connection_threshold"`
	BytesThreshold      int `yaml:"bytes_threshold"`
	SuspiciousSpike     int `yaml:"suspicious_spike"`
	PortScanThreshold   int `yaml:"port_scan_threshold"`
	WindowSeconds       int `yaml:"window_seconds"`
}

type AlertsConfig struct {
	DiscordWebhook string `yaml:"discord_webhook"`
	SlackWebhook   string `yaml:"slack_webhook"`
	Email          string `yaml:"email"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Rotate bool   `yaml:"rotate"`
}

// APIConfig configures the optional REST API.
type APIConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Token       string `yaml:"token"`
	BindAddress string `yaml:"bind_address"`
	RateLimit   int    `yaml:"rate_limit"`
	RateBurst   int    `yaml:"rate_burst"`
}

// DefaultConfig returns the safe baseline configuration for a host-based deployment.
func DefaultConfig() Config {
	return Config{
		General:   GeneralConfig{LogDir: "/var/log/digitdojo-shield", StateDir: "/var/lib/digitdojo-shield", HostBased: true},
		Firewall:  FirewallConfig{Backend: "auto", RateLimitPerSecond: 200, ConnectionLimit: 200, TemporaryBanSeconds: 600},
		Detection: DetectionConfig{PacketThreshold: 2000, ConnectionThreshold: 200, BytesThreshold: 1024 * 1024, SuspiciousSpike: 5, PortScanThreshold: 10, WindowSeconds: 30},
		Alerts:    AlertsConfig{},
		Logging:   LoggingConfig{Level: "info", Rotate: true},
		API:       APIConfig{Enabled: false, BindAddress: "127.0.0.1:9090", RateLimit: 30, RateBurst: 60},
	}
}

// Validate ensures the configuration is safe and usable.
func (c Config) Validate() error {
	if err := validatePath(c.General.LogDir, "general.log_dir"); err != nil {
		return err
	}
	if err := validatePath(c.General.StateDir, "general.state_dir"); err != nil {
		return err
	}
	if _, err := backend.ParseName(c.Firewall.Backend); err != nil {
		return fmt.Errorf("firewall.backend: %w", err)
	}
	if c.Firewall.RateLimitPerSecond <= 0 {
		return fmt.Errorf("firewall.rate_limit_per_second must be > 0")
	}
	if c.Firewall.ConnectionLimit <= 0 {
		return fmt.Errorf("firewall.connection_limit must be > 0")
	}
	if c.Detection.WindowSeconds <= 0 {
		return fmt.Errorf("detection.window_seconds must be > 0")
	}
	if c.Detection.PacketThreshold <= 0 {
		return fmt.Errorf("detection.packet_threshold must be > 0")
	}
	if c.API.Enabled {
		if strings.TrimSpace(c.API.Token) == "" {
			return fmt.Errorf("api.token is required when api.enabled is true")
		}
		if c.API.RateLimit <= 0 {
			return fmt.Errorf("api.rate_limit must be > 0")
		}
		if c.API.RateBurst <= 0 {
			return fmt.Errorf("api.rate_burst must be > 0")
		}
		if c.API.BindAddress == "" {
			return fmt.Errorf("api.bind_address is required when api.enabled is true")
		}
		if err := validateBindAddress(c.API.BindAddress); err != nil {
			return err
		}
	}
	return nil
}

// ValidateIP enforces that only valid, non-local IP addresses are used for allow/block lists.
func (c Config) ValidateIP(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	if parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() || parsed.IsUnspecified() {
		return fmt.Errorf("refusing to use loopback, link-local, or unspecified IP: %s", ip)
	}
	if parsed.IsMulticast() {
		return fmt.Errorf("refusing to use multicast IP: %s", ip)
	}
	return nil
}

// EnsureDir creates a directory tree with safe permissions.
func EnsureDir(path string) error {
	return os.MkdirAll(path, 0o755)
}

// EnsureConfigPath creates the parent directory for a configuration file.
func EnsureConfigPath(path string) error {
	dir := filepath.Dir(path)
	return EnsureDir(dir)
}

// ResolvePath normalizes a path for the local filesystem.
func ResolvePath(path string) string {
	if strings.HasPrefix(path, "/") {
		return filepath.Clean(path)
	}
	return filepath.Clean(path)
}

func validatePath(path, field string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%s is required", field)
	}
	if !filepath.IsAbs(path) && !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "\\") {
		return fmt.Errorf("%s must be an absolute path: %s", field, path)
	}
	cleaned := filepath.Clean(path)
	parts := strings.Split(cleaned, string(filepath.Separator))
	for _, part := range parts {
		if part == ".." {
			return fmt.Errorf("%s must not contain path traversal: %s", field, path)
		}
	}
	return nil
}

func validateBindAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid bind address %q: %w", address, err)
	}
	if host != "" && host != "0.0.0.0" && host != "::" && host != "127.0.0.1" && host != "localhost" && net.ParseIP(host) == nil {
		return fmt.Errorf("unsupported bind host %q", host)
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return fmt.Errorf("invalid bind port %q", port)
	}
	return nil
}
