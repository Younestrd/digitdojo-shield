package storage

import (
	"os"
	"path/filepath"
	"testing"

	"digitdojo-shield/internal/config"
)

func TestStatePersistsAcrossInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "shield-state.json")
	cfg := config.DefaultConfig()
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	state, err := NewState(cfg, store)
	if err != nil {
		t.Fatalf("create state: %v", err)
	}
	if err := state.AddBlacklist("8.8.8.8"); err != nil {
		t.Fatalf("add blacklist: %v", err)
	}
	if err := state.AddWhitelist("1.1.1.1"); err != nil {
		t.Fatalf("add whitelist: %v", err)
	}

	reopenedStore, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	reopened, err := NewState(cfg, reopenedStore)
	if err != nil {
		t.Fatalf("reload state: %v", err)
	}
	if !reopened.Blacklist().Contains("8.8.8.8") {
		t.Fatalf("persisted blacklist entry was not restored")
	}
	if !reopened.Whitelist().Contains("1.1.1.1") {
		t.Fatalf("persisted whitelist entry was not restored")
	}
}

func TestStateRejectsListConflictWithoutChangingDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shield-state.json")
	cfg := config.DefaultConfig()
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	state, err := NewState(cfg, store)
	if err != nil {
		t.Fatalf("create state: %v", err)
	}
	if err := state.AddWhitelist("8.8.4.4"); err != nil {
		t.Fatalf("add whitelist: %v", err)
	}
	if err := state.AddBlacklist("8.8.4.4"); err == nil {
		t.Fatalf("expected conflicting blacklist entry to fail")
	}
	snapshot, err := store.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if len(snapshot.Blacklist) != 0 || len(snapshot.Whitelist) != 1 {
		t.Fatalf("unexpected persisted state: %+v", snapshot)
	}
}

func TestFileStoreRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shield-state.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"blacklist":[],"whitelist":[],"updated_at":"","unknown":true}`), 0o600); err != nil {
		t.Fatalf("write corrupt state: %v", err)
	}
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatalf("expected unknown field to be rejected")
	}
}
