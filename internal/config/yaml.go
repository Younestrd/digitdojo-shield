package config

import (
	"fmt"
	"os"
	"strings"
)

func LoadFromFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	cfg := DefaultConfig()
	if err := parseSimpleYAML(data, &cfg); err != nil {
		return Config{}, err
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func parseSimpleYAML(data []byte, cfg *Config) error {
	lines := strings.Split(string(data), "\n")
	var currentSection string
	for idx, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasSuffix(trimmed, ":") && !strings.Contains(trimmed, " ") {
			currentSection = strings.TrimSuffix(trimmed, ":")
			if !isKnownSection(currentSection) {
				return fmt.Errorf("line %d: unknown section %q", idx+1, currentSection)
			}
			continue
		}
		if strings.Contains(trimmed, ":") {
			key, value := parseKeyValue(trimmed)
			if currentSection == "" {
				return fmt.Errorf("line %d: key %q outside a section", idx+1, key)
			}
			if !isKnownKey(currentSection, key) {
				return fmt.Errorf("line %d: unknown key %q in section %q", idx+1, key, currentSection)
			}
			if err := applyField(cfg, currentSection, key, value); err != nil {
				return fmt.Errorf("line %d: %w", idx+1, err)
			}
			continue
		}
		return fmt.Errorf("line %d: malformed YAML entry %q", idx+1, trimmed)
	}
	return nil
}

func parseKeyValue(line string) (string, string) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

func applyField(cfg *Config, section, key, value string) error {
	switch section {
	case "general":
		return applyGeneralField(cfg, key, value)
	case "firewall":
		return applyFirewallField(cfg, key, value)
	case "detection":
		return applyDetectionField(cfg, key, value)
	case "alerts":
		return applyAlertsField(cfg, key, value)
	case "logging":
		return applyLoggingField(cfg, key, value)
	case "api":
		return applyAPIField(cfg, key, value)
	default:
		return fmt.Errorf("unsupported section %q", section)
	}
}

func applyGeneralField(cfg *Config, key, value string) error {
	switch key {
	case "log_dir":
		cfg.General.LogDir = value
	case "state_dir":
		cfg.General.StateDir = value
	case "host_based":
		cfg.General.HostBased = parseBool(value)
	default:
		return fmt.Errorf("unsupported key %q", key)
	}
	return nil
}

func applyFirewallField(cfg *Config, key, value string) error {
	switch key {
	case "backend":
		cfg.Firewall.Backend = value
	case "rate_limit_per_second":
		cfg.Firewall.RateLimitPerSecond = parseInt(value)
	case "connection_limit":
		cfg.Firewall.ConnectionLimit = parseInt(value)
	case "temporary_ban_seconds":
		cfg.Firewall.TemporaryBanSeconds = parseInt(value)
	default:
		return fmt.Errorf("unsupported key %q", key)
	}
	return nil
}

func applyDetectionField(cfg *Config, key, value string) error {
	switch key {
	case "packet_threshold":
		cfg.Detection.PacketThreshold = parseInt(value)
	case "connection_threshold":
		cfg.Detection.ConnectionThreshold = parseInt(value)
	case "bytes_threshold":
		cfg.Detection.BytesThreshold = parseInt(value)
	case "suspicious_spike":
		cfg.Detection.SuspiciousSpike = parseInt(value)
	case "port_scan_threshold":
		cfg.Detection.PortScanThreshold = parseInt(value)
	case "window_seconds":
		cfg.Detection.WindowSeconds = parseInt(value)
	default:
		return fmt.Errorf("unsupported key %q", key)
	}
	return nil
}

func applyAlertsField(cfg *Config, key, value string) error {
	switch key {
	case "discord_webhook":
		cfg.Alerts.DiscordWebhook = value
	case "slack_webhook":
		cfg.Alerts.SlackWebhook = value
	case "email":
		cfg.Alerts.Email = value
	default:
		return fmt.Errorf("unsupported key %q", key)
	}
	return nil
}

func applyLoggingField(cfg *Config, key, value string) error {
	switch key {
	case "level":
		cfg.Logging.Level = value
	case "rotate":
		cfg.Logging.Rotate = parseBool(value)
	default:
		return fmt.Errorf("unsupported key %q", key)
	}
	return nil
}

func applyAPIField(cfg *Config, key, value string) error {
	switch key {
	case "enabled":
		cfg.API.Enabled = parseBool(value)
	case "token":
		cfg.API.Token = value
	case "bind_address":
		cfg.API.BindAddress = value
	case "rate_limit":
		cfg.API.RateLimit = parseInt(value)
	case "rate_burst":
		cfg.API.RateBurst = parseInt(value)
	default:
		return fmt.Errorf("unsupported key %q", key)
	}
	return nil
}

func isKnownSection(section string) bool {
	switch section {
	case "general", "firewall", "detection", "alerts", "logging", "api":
		return true
	default:
		return false
	}
}

func isKnownKey(section, key string) bool {
	switch section {
	case "general":
		return key == "log_dir" || key == "state_dir" || key == "host_based"
	case "firewall":
		return key == "backend" || key == "rate_limit_per_second" || key == "connection_limit" || key == "temporary_ban_seconds"
	case "detection":
		return key == "packet_threshold" || key == "connection_threshold" || key == "bytes_threshold" || key == "suspicious_spike" || key == "port_scan_threshold" || key == "window_seconds"
	case "alerts":
		return key == "discord_webhook" || key == "slack_webhook" || key == "email"
	case "logging":
		return key == "level" || key == "rotate"
	case "api":
		return key == "enabled" || key == "token" || key == "bind_address" || key == "rate_limit" || key == "rate_burst"
	default:
		return false
	}
}

func parseBool(value string) bool {
	switch strings.ToLower(value) {
	case "true", "yes", "on", "1":
		return true
	default:
		return false
	}
}

func parseInt(value string) int {
	var i int
	fmt.Sscanf(value, "%d", &i)
	return i
}
