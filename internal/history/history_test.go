package history

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStorePersistsAttackLifecycle(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "history.json"))
	if err != nil {
		t.Fatal(err)
	}
	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	attack := Attack{Type: "udp_flood", Severity: "high"}
	if err := store.Record(Metric{Timestamp: first, PacketsPerSecond: 42}, []Attack{attack}); err != nil {
		t.Fatal(err)
	}
	if err := store.Record(Metric{Timestamp: first.Add(time.Minute)}, nil); err != nil {
		t.Fatal(err)
	}
	attacks, total := store.Attacks(0, 10)
	if total != 1 || attacks[0].ResolvedAt == nil {
		t.Fatalf("unexpected attacks: %#v", attacks)
	}
	reloaded, err := New(filepath.Join(filepath.Dir(store.path), "history.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(reloaded.Metrics(time.Time{})); got != 2 {
		t.Fatalf("metrics=%d", got)
	}
}
