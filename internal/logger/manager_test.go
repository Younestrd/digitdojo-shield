package logger

import (
	"path/filepath"
	"testing"
	"time"
)

func TestManagerQueriesAndStreamsEntries(t *testing.T) {
	manager, err := NewManager(filepath.Join(t.TempDir(), "shield.log"), 1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan Entry, 1)
	unsubscribe := manager.Subscribe(func(entry Entry) { received <- entry })
	defer unsubscribe()
	if err := manager.Write(Entry{Timestamp: time.Now().UTC(), Level: "warn", Category: "API", Message: "token denied"}); err != nil {
		t.Fatal(err)
	}
	select {
	case entry := <-received:
		if entry.Level != "WARN" {
			t.Fatalf("level=%s", entry.Level)
		}
	case <-time.After(time.Second):
		t.Fatal("stream timeout")
	}
	entries, total, err := manager.Query(Query{Search: "denied", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(entries) != 1 {
		t.Fatalf("entries=%d total=%d", len(entries), total)
	}
}
