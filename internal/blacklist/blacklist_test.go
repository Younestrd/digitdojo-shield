package blacklist

import (
    "testing"

    "digitdojo-shield/internal/config"
)

func TestAddAndList(t *testing.T) {
    cfg := config.DefaultConfig()
    mgr := NewManager()
    if err := mgr.Add(cfg, "1.2.3.4"); err != nil {
        t.Fatalf("expected valid IP to be added, got %v", err)
    }
    if !mgr.Contains("1.2.3.4") {
        t.Fatalf("expected blacklist to contain the added IP")
    }
    if len(mgr.List()) != 1 {
        t.Fatalf("expected one entry, got %d", len(mgr.List()))
    }
}
