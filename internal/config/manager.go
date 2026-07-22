package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Change records an atomically-applied configuration revision.
type Change struct {
	Version   int       `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Checksum  string    `json:"checksum"`
	Summary   string    `json:"summary"`
}

// Manager is the only component authorized to persist Shield configuration.
type Manager struct {
	mu      sync.RWMutex
	path    string
	current Config
	version int
	history []Change
	apply   func(Config) error
}

func NewManager(path string, initial Config) (*Manager, error) {
	if err := initial.Validate(); err != nil {
		return nil, err
	}
	if path == "" {
		return &Manager{current: initial}, nil
	}
	path = filepath.Clean(path)
	loaded, err := LoadFromFile(path)
	if err != nil {
		return nil, err
	}
	manager := &Manager{path: path, current: loaded}
	data, err := encodeConfig(loaded)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	manager.version = 1
	manager.history = []Change{{Version: 1, Timestamp: time.Now().UTC(), Checksum: hex.EncodeToString(digest[:]), Summary: "initial configuration"}}
	if err := os.WriteFile(manager.backupPath(1), data, 0o600); err != nil {
		return nil, err
	}
	if err := manager.saveHistory(); err != nil {
		return nil, err
	}
	_ = initial
	return manager, nil
}
func NewMemoryManager(initial Config) (*Manager, error) { return NewManager("", initial) }
func (m *Manager) Current() Config                      { m.mu.RLock(); defer m.mu.RUnlock(); return m.current }
func (m *Manager) History() []Change {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]Change(nil), m.history...)
}
func (m *Manager) SetApply(apply func(Config) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.apply = apply
}
func (m *Manager) Reload() error {
	if m.path == "" {
		return fmt.Errorf("configuration reload is unavailable without a configuration path")
	}
	candidate, err := LoadFromFile(m.path)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applyLocked(candidate, "reload")
}
func (m *Manager) Update(candidate Config, summary string) error {
	if err := candidate.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.path == "" {
		return fmt.Errorf("configuration updates are unavailable without a configuration path")
	}
	previous := m.current
	previousData, err := encodeConfig(previous)
	if err != nil {
		return err
	}
	candidateData, err := encodeConfig(candidate)
	if err != nil {
		return err
	}
	if err := m.writeAtomically(candidateData); err != nil {
		return err
	}
	reloaded, err := LoadFromFile(m.path)
	if err == nil {
		err = m.applyLocked(reloaded, summary)
	}
	if err == nil {
		return nil
	}
	if rollbackErr := m.writeAtomically(previousData); rollbackErr != nil {
		return fmt.Errorf("apply configuration: %w; rollback configuration: %v", err, rollbackErr)
	}
	return fmt.Errorf("apply configuration: %w; configuration was rolled back", err)
}
func (m *Manager) Rollback(version int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.path == "" {
		return fmt.Errorf("configuration rollback is unavailable without a configuration path")
	}
	if version < 1 || version > len(m.history) {
		return fmt.Errorf("unknown configuration version %d", version)
	}
	data, err := os.ReadFile(m.backupPath(version))
	if err != nil {
		return err
	}
	candidate, err := loadBytes(data)
	if err != nil {
		return err
	}
	previousData, err := encodeConfig(m.current)
	if err != nil {
		return err
	}
	if err = m.writeAtomically(data); err != nil {
		return err
	}
	if err = m.applyLocked(candidate, fmt.Sprintf("rollback to version %d", version)); err == nil {
		return nil
	}
	if rollbackErr := m.writeAtomically(previousData); rollbackErr != nil {
		return fmt.Errorf("rollback apply: %w; restore current config: %v", err, rollbackErr)
	}
	return err
}
func (m *Manager) applyLocked(candidate Config, summary string) error {
	if m.apply != nil {
		if err := m.apply(candidate); err != nil {
			return err
		}
	}
	m.current = candidate
	m.version++
	data, err := encodeConfig(candidate)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	change := Change{Version: m.version, Timestamp: time.Now().UTC(), Checksum: hex.EncodeToString(digest[:]), Summary: summary}
	m.history = append(m.history, change)
	if m.path != "" {
		if err := os.WriteFile(m.backupPath(change.Version), data, 0o600); err != nil {
			return err
		}
		_ = m.saveHistory()
	}
	return nil
}
func (m *Manager) writeAtomically(data []byte) error {
	directory := filepath.Dir(m.path)
	temporary, err := os.CreateTemp(directory, ".shield-config-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(name)
		}
	}()
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
	if err := os.Rename(name, m.path); err != nil {
		return err
	}
	directoryFile, err := os.Open(directory)
	if err == nil {
		_ = directoryFile.Sync()
		_ = directoryFile.Close()
	}
	committed = true
	return nil
}
func (m *Manager) backupPath(version int) string { return fmt.Sprintf("%s.v%d", m.path, version) }
func (m *Manager) saveHistory() error {
	data, err := json.Marshal(m.history)
	if err != nil {
		return err
	}
	return os.WriteFile(m.path+".history.json", data, 0o600)
}
func encodeConfig(cfg Config) ([]byte, error) { return yaml.Marshal(cfg) }
func loadBytes(data []byte) (Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
