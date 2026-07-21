package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReloadableConfigReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte("general:\n  log_dir: /tmp/logs\n  state_dir: /tmp/state\n  host_based: true\nfirewall:\n  rate_limit_per_second: 100\n  connection_limit: 50\n  temporary_ban_seconds: 300\ndetection:\n  packet_threshold: 500\n  connection_threshold: 100\n  window_seconds: 20\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	rc, err := NewReloadableConfig(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if err := rc.Reload(); err != nil {
		t.Fatalf("reload config: %v", err)
	}
}
