// Package history persists daemon-observed metrics and attack lifecycles.
package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const version = 1

type Metric struct {
	Timestamp            time.Time `json:"timestamp"`
	PacketsPerSecond     int       `json:"packets_per_second"`
	ConnectionsPerSecond int       `json:"connections_per_second"`
	BytesPerSecond       int       `json:"bytes_per_second"`
	Blocked              int       `json:"blocked"`
	Signals              int       `json:"signals"`
}

type Attack struct {
	ID         string     `json:"id"`
	Type       string     `json:"type"`
	Severity   string     `json:"severity"`
	StartedAt  time.Time  `json:"started_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	Mitigation string     `json:"mitigation"`
}

type snapshot struct {
	Version int      `json:"version"`
	Metrics []Metric `json:"metrics"`
	Attacks []Attack `json:"attacks"`
}

type Store struct {
	path    string
	mu      sync.RWMutex
	metrics []Metric
	attacks []Attack
}

func New(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("history path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: path}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return s, s.saveLocked()
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var data snapshot
	if err := json.NewDecoder(file).Decode(&data); err != nil {
		return nil, fmt.Errorf("decode history: %w", err)
	}
	if data.Version != version {
		return nil, fmt.Errorf("unsupported history version %d", data.Version)
	}
	s.metrics, s.attacks = data.Metrics, data.Attacks
	return s, nil
}

func (s *Store) Record(metric Metric, signals []Attack) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if metric.Timestamp.IsZero() {
		metric.Timestamp = time.Now().UTC()
	}
	s.metrics = append(s.metrics, metric)
	if len(s.metrics) > 43200 {
		s.metrics = append([]Metric(nil), s.metrics[len(s.metrics)-43200:]...)
	}
	now := metric.Timestamp
	active := make(map[string]bool, len(signals))
	for _, attack := range signals {
		key := attack.Type + "\x00" + attack.Severity
		active[key] = true
		if s.findActive(key) < 0 {
			attack.ID = fmt.Sprintf("%d-%s", now.UnixNano(), attack.Type)
			attack.StartedAt = now
			attack.Mitigation = "detection only"
			s.attacks = append(s.attacks, attack)
		}
	}
	for index := range s.attacks {
		if s.attacks[index].ResolvedAt == nil && !active[s.attacks[index].Type+"\x00"+s.attacks[index].Severity] {
			resolved := now
			s.attacks[index].ResolvedAt = &resolved
		}
	}
	return s.saveLocked()
}

func (s *Store) findActive(key string) int {
	for i := len(s.attacks) - 1; i >= 0; i-- {
		if s.attacks[i].ResolvedAt == nil && s.attacks[i].Type+"\x00"+s.attacks[i].Severity == key {
			return i
		}
	}
	return -1
}
func (s *Store) Metrics(since time.Time) []Metric {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Metric, 0)
	for _, metric := range s.metrics {
		if !metric.Timestamp.Before(since) {
			result = append(result, metric)
		}
	}
	return result
}
func (s *Store) Attacks(offset, limit int) ([]Attack, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copyOf := append([]Attack(nil), s.attacks...)
	sort.Slice(copyOf, func(i, j int) bool { return copyOf[i].StartedAt.After(copyOf[j].StartedAt) })
	total := len(copyOf)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return copyOf[offset:end], total
}
func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(snapshot{Version: version, Metrics: s.metrics, Attacks: s.attacks}, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".shield-history-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, s.path)
}
