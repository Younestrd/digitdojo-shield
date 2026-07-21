package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromFileParsesSimpleYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	content := []byte("general:\n  log_dir: /tmp/logs\n  state_dir: /tmp/state\n  host_based: true\nfirewall:\n  backend: iptables\n  rate_limit_per_second: 100\n  connection_limit: 50\n  temporary_ban_seconds: 300\ndetection:\n  packet_threshold: 500\n  connection_threshold: 100\n  bytes_threshold: 524288\n  suspicious_spike: 3\n  port_scan_threshold: 8\n  window_seconds: 20\nlogging:\n  level: warn\n  rotate: true\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("expected YAML parse to succeed, got %v", err)
	}
	if cfg.General.LogDir != "/tmp/logs" {
		t.Fatalf("expected log dir override, got %s", cfg.General.LogDir)
	}
	if cfg.Detection.PacketThreshold != 500 {
		t.Fatalf("expected packet threshold override, got %d", cfg.Detection.PacketThreshold)
	}
}
