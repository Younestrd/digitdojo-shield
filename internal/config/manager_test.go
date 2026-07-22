package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestManagerRollsBackFailedApply(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config.yml")
	cfg := DefaultConfig()
	cfg.General.LogDir = filepath.Join(root, "log")
	cfg.General.StateDir = filepath.Join(root, "state")
	data, err := encodeConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	manager.SetApply(func(Config) error { return fmt.Errorf("reject") })
	candidate := cfg
	candidate.Detection.PacketThreshold++
	if err := manager.Update(candidate, "test"); err == nil {
		t.Fatal("expected update error")
	}
	loaded, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Detection.PacketThreshold != cfg.Detection.PacketThreshold {
		t.Fatal("configuration not rolled back")
	}
	if len(manager.History()) != 1 {
		t.Fatalf("history length=%d", len(manager.History()))
	}
}
