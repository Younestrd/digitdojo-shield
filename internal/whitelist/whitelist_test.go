package whitelist

import (
    "testing"

    "digitdojo-shield/internal/config"
)

func TestAddAndList(t *testing.T) {
    cfg := config.DefaultConfig()
    mgr := NewManager()
    if err := mgr.Add(cfg, "8.8.8.8"); err != nil {
        t.Fatalf("expected valid IP to be added, got %v", err)
    }
    if !mgr.Contains("8.8.8.8") {
        t.Fatalf("expected whitelist to contain the added IP")
    }
    if len(mgr.List()) != 1 {
        t.Fatalf("expected one entry, got %d", len(mgr.List()))
    }
}
