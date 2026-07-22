package audit

import (
	"path/filepath"
	"testing"
	"time"
)

func TestManagerPersistsAndStreams(t *testing.T) {
	manager, err := New(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	stream := make(chan Record, 1)
	unsubscribe := manager.Subscribe(func(record Record) { stream <- record })
	defer unsubscribe()
	if err := manager.Record(Record{User: "api-token", Action: "config.update", Resource: "config", RequestID: "r1"}); err != nil {
		t.Fatal(err)
	}
	select {
	case record := <-stream:
		if record.ID == "" || record.Timestamp.IsZero() {
			t.Fatal("missing audit identity")
		}
	case <-time.After(time.Second):
		t.Fatal("stream timeout")
	}
	records, total, err := manager.Query(Query{Action: "config.update", Limit: 10})
	if err != nil || total != 1 || len(records) != 1 {
		t.Fatalf("records=%d total=%d err=%v", len(records), total, err)
	}
}
