package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"digitdojo-shield/internal/config"
)

func TestApplicationStartsAndStopsAllOwnedResources(t *testing.T) {
	root := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.General.LogDir = filepath.Join(root, "logs")
	cfg.General.StateDir = filepath.Join(root, "state")
	cfg.Detection.WindowSeconds = 1
	cfg.API.Enabled = false

	application, err := New(cfg)
	if err != nil {
		t.Fatalf("initialize application: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- application.Run(ctx)
	}()
	select {
	case <-application.Ready():
	case <-time.After(time.Second):
		t.Fatalf("application did not become ready")
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("run application: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("application did not shut down")
	}

	if _, err := os.Stat(filepath.Join(cfg.General.StateDir, "shield-state.json")); err != nil {
		t.Fatalf("persistent state was not initialized: %v", err)
	}
	logData, err := os.ReadFile(filepath.Join(cfg.General.LogDir, "shieldd.json.log"))
	if err != nil {
		t.Fatalf("read runtime log: %v", err)
	}
	logText := string(logData)
	if !strings.Contains(logText, eventRuntimeStarted) || !strings.Contains(logText, eventRuntimeStopped) {
		t.Fatalf("runtime lifecycle events were not logged: %s", logText)
	}
	if err := application.Run(context.Background()); err == nil {
		t.Fatalf("expected a second run to be rejected")
	}
}
