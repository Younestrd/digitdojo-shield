package blacklist

import (
	"fmt"
	"testing"

	"digitdojo-shield/internal/config"
)

func TestLargeBlacklist(t *testing.T) {
	cfg := config.DefaultConfig()
	mgr := NewManager()
	for i := 0; i < 10000; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i%250)
		if err := mgr.Add(cfg, ip); err != nil {
			t.Fatalf("expected large blacklist to be added: %v", err)
		}
	}
	if len(mgr.List()) != 250 {
		t.Fatalf("expected 250 unique entries, got %d", len(mgr.List()))
	}
}
