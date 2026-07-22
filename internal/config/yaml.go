package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

var allowedYAMLKeys = map[string]map[string]bool{
	"general":   {"log_dir": true, "state_dir": true, "host_based": true},
	"firewall":  {"backend": true, "rate_limit_per_second": true, "connection_limit": true, "temporary_ban_seconds": true},
	"detection": {"packet_threshold": true, "connection_threshold": true, "bytes_threshold": true, "suspicious_spike": true, "port_scan_threshold": true, "window_seconds": true},
	"alerts":    {"discord_webhook": true, "slack_webhook": true, "email": true},
	"logging":   {"level": true, "rotate": true},
	"api":       {"enabled": true, "token": true, "bind_address": true, "rate_limit": true, "rate_burst": true},
}

func LoadFromFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return Config{}, fmt.Errorf("parse YAML: %w", err)
	}
	if err := validateYAML(&document); err != nil {
		return Config{}, err
	}
	cfg := DefaultConfig()
	if err := document.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode YAML: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func validateYAML(document *yaml.Node) error {
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("configuration must be a YAML mapping")
	}
	root := document.Content[0]
	seen := map[string]bool{}
	for i := 0; i < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		if seen[key.Value] {
			return fmt.Errorf("line %d: duplicate section %q", key.Line, key.Value)
		}
		seen[key.Value] = true
		keys, ok := allowedYAMLKeys[key.Value]
		if !ok {
			return fmt.Errorf("line %d: unknown section %q", key.Line, key.Value)
		}
		if value.Kind != yaml.MappingNode {
			return fmt.Errorf("line %d: section %q must be a mapping", value.Line, key.Value)
		}
		sectionSeen := map[string]bool{}
		for j := 0; j < len(value.Content); j += 2 {
			field := value.Content[j]
			if sectionSeen[field.Value] {
				return fmt.Errorf("line %d: duplicate key %q in section %q", field.Line, field.Value, key.Value)
			}
			sectionSeen[field.Value] = true
			if !keys[field.Value] {
				return fmt.Errorf("line %d: unknown key %q in section %q", field.Line, field.Value, key.Value)
			}
		}
	}
	return nil
}
