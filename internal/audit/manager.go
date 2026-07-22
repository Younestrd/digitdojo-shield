// Package audit records immutable management actions separately from operational logs.
package audit

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Record struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	User      string    `json:"user"`
	SourceIP  string    `json:"source_ip"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Previous  string    `json:"previous_value,omitempty"`
	New       string    `json:"new_value,omitempty"`
	Result    string    `json:"result"`
	RequestID string    `json:"request_id"`
}
type Query struct {
	Search, Action, Resource, Result string
	Offset, Limit                    int
}
type Manager struct {
	mu          sync.Mutex
	path        string
	subscribers map[uint64]func(Record)
	next        uint64
}

func New(path string) (*Manager, error) {
	if path == "" {
		return nil, fmt.Errorf("audit log path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return &Manager{path: path, subscribers: map[uint64]func(Record){}}, nil
}
func (m *Manager) Record(record Record) error {
	if record.ID == "" {
		id, err := NewID()
		if err != nil {
			return err
		}
		record.ID = id
	}
	if record.Timestamp.IsZero() {
		record.Timestamp = time.Now().UTC()
	}
	if record.Result == "" {
		record.Result = "success"
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	file, err := os.OpenFile(m.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = file.Write(append(data, '\n'))
	if syncErr := file.Sync(); err == nil {
		err = syncErr
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	for _, fn := range m.subscribers {
		fn(record)
	}
	return nil
}
func (m *Manager) Subscribe(fn func(Record)) func() {
	m.mu.Lock()
	id := m.next
	m.next++
	m.subscribers[id] = fn
	m.mu.Unlock()
	return func() { m.mu.Lock(); delete(m.subscribers, id); m.mu.Unlock() }
}
func (m *Manager) Query(q Query) ([]Record, int, error) {
	if q.Limit < 1 {
		q.Limit = 100
	}
	if q.Limit > 500 {
		q.Limit = 500
	}
	file, err := os.Open(m.path)
	if os.IsNotExist(err) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	result := make([]Record, 0, q.Limit)
	total := 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var record Record
		if json.Unmarshal(scanner.Bytes(), &record) != nil || !matches(record, q) {
			continue
		}
		if total >= q.Offset && len(result) < q.Limit {
			result = append(result, record)
		}
		total++
	}
	return result, total, scanner.Err()
}
func (m *Manager) Export(q Query, w io.Writer) error {
	records, _, err := m.Query(Query{Search: q.Search, Action: q.Action, Resource: q.Resource, Result: q.Result, Limit: 500})
	if err != nil {
		return err
	}
	for _, record := range records {
		data, _ := json.Marshal(record)
		if _, err := w.Write(append(data, '\n')); err != nil {
			return err
		}
	}
	return nil
}
func matches(record Record, q Query) bool {
	if q.Action != "" && !strings.EqualFold(record.Action, q.Action) {
		return false
	}
	if q.Resource != "" && !strings.EqualFold(record.Resource, q.Resource) {
		return false
	}
	if q.Result != "" && !strings.EqualFold(record.Result, q.Result) {
		return false
	}
	needle := strings.ToLower(q.Search)
	return needle == "" || strings.Contains(strings.ToLower(fmt.Sprintf("%v", record)), needle)
}
func NewID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[0:4]) + "-" + hex.EncodeToString(bytes[4:6]) + "-" + hex.EncodeToString(bytes[6:8]) + "-" + hex.EncodeToString(bytes[8:10]) + "-" + hex.EncodeToString(bytes[10:]), nil
}
