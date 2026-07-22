package logger

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Entry struct {
	Timestamp time.Time         `json:"timestamp"`
	Level     string            `json:"level"`
	Category  string            `json:"category"`
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields,omitempty"`
}
type Query struct {
	Search, Level, Category string
	From, To                time.Time
	Offset, Limit           int
	Desc                    bool
}
type Manager struct {
	mu          sync.Mutex
	path        string
	maxSize     int64
	retention   int
	subscribers map[uint64]func(Entry)
	next        uint64
}

func NewManager(path string, maxSize int64, retention int) (*Manager, error) {
	if path == "" {
		return nil, fmt.Errorf("log path is required")
	}
	if maxSize <= 0 {
		maxSize = 10 << 20
	}
	if retention < 1 {
		retention = 7
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	return &Manager{path: path, maxSize: maxSize, retention: retention, subscribers: map[uint64]func(Entry){}}, nil
}
func (m *Manager) Subscribe(fn func(Entry)) func() {
	m.mu.Lock()
	id := m.next
	m.next++
	m.subscribers[id] = fn
	m.mu.Unlock()
	return func() { m.mu.Lock(); delete(m.subscribers, id); m.mu.Unlock() }
}
func (m *Manager) Write(entry Entry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	entry.Level = normalizeLevel(entry.Level)
	if entry.Category == "" {
		entry.Category = "Runtime"
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.rotateLocked(int64(len(data) + 1)); err != nil {
		return err
	}
	file, err := os.OpenFile(m.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(append(data, '\n'))
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, fn := range m.subscribers {
		fn(entry)
	}
	return nil
}
func (m *Manager) Query(query Query) ([]Entry, int, error) {
	if query.Limit < 1 {
		query.Limit = 100
	}
	if query.Limit > 500 {
		query.Limit = 500
	}
	file, err := os.Open(m.path)
	if os.IsNotExist(err) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	entries := make([]Entry, 0, query.Limit)
	total := 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var entry Entry
		if json.Unmarshal(scanner.Bytes(), &entry) != nil || !matches(entry, query) {
			continue
		}
		if total >= query.Offset && len(entries) < query.Limit {
			entries = append(entries, entry)
		}
		total++
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, err
	}
	if query.Desc {
		sort.Slice(entries, func(i, j int) bool { return entries[i].Timestamp.After(entries[j].Timestamp) })
	}
	return entries, total, nil
}
func (m *Manager) Export(query Query, format string, w io.Writer) error {
	entries, _, err := m.Query(Query{Search: query.Search, Level: query.Level, Category: query.Category, From: query.From, To: query.To, Limit: 500})
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if format == "txt" {
			if _, err := fmt.Fprintf(w, "%s [%s] [%s] %s %v\n", entry.Timestamp.Format(time.RFC3339), entry.Level, entry.Category, entry.Message, entry.Fields); err != nil {
				return err
			}
		} else {
			data, _ := json.Marshal(entry)
			if _, err := w.Write(append(data, '\n')); err != nil {
				return err
			}
		}
	}
	return nil
}
func (m *Manager) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return os.WriteFile(m.path, nil, 0o600)
}
func (m *Manager) rotateLocked(next int64) error {
	info, err := os.Stat(m.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Size()+next <= m.maxSize {
		return nil
	}
	source, err := os.Open(m.path)
	if err != nil {
		return err
	}
	archive := fmt.Sprintf("%s.%s.gz", m.path, time.Now().UTC().Format("20060102T150405.000000000Z"))
	destination, err := os.OpenFile(archive, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		source.Close()
		return err
	}
	zip := gzip.NewWriter(destination)
	_, copyErr := io.Copy(zip, source)
	zipErr := zip.Close()
	source.Close()
	destination.Close()
	if copyErr != nil {
		return copyErr
	}
	if zipErr != nil {
		return zipErr
	}
	if err := os.Truncate(m.path, 0); err != nil {
		return err
	}
	archives, _ := filepath.Glob(m.path + ".*.gz")
	sort.Strings(archives)
	for len(archives) > m.retention {
		_ = os.Remove(archives[0])
		archives = archives[1:]
	}
	return nil
}
func matches(entry Entry, q Query) bool {
	if q.Level != "" && !strings.EqualFold(entry.Level, q.Level) {
		return false
	}
	if q.Category != "" && !strings.EqualFold(entry.Category, q.Category) {
		return false
	}
	if !q.From.IsZero() && entry.Timestamp.Before(q.From) {
		return false
	}
	if !q.To.IsZero() && entry.Timestamp.After(q.To) {
		return false
	}
	needle := strings.ToLower(q.Search)
	return needle == "" || strings.Contains(strings.ToLower(entry.Message), needle) || strings.Contains(strings.ToLower(fmt.Sprint(entry.Fields)), needle)
}
func normalizeLevel(level string) string {
	switch strings.ToUpper(level) {
	case "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL":
		return strings.ToUpper(level)
	default:
		return "INFO"
	}
}
