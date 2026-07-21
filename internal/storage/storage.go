package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"digitdojo-shield/internal/blacklist"
	"digitdojo-shield/internal/config"
	"digitdojo-shield/internal/whitelist"
)

const currentVersion = 1

// Snapshot is the versioned state persisted by the daemon.
type Snapshot struct {
	Version   int      `json:"version"`
	Blacklist []string `json:"blacklist"`
	Whitelist []string `json:"whitelist"`
	UpdatedAt string   `json:"updated_at"`
}

// FileStore persists a complete snapshot using an atomic replacement on Linux.
type FileStore struct {
	path string
	mu   sync.Mutex
}

func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, fmt.Errorf("state file path is required")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secure state directory: %w", err)
	}
	return &FileStore{path: path}, nil
}

func (s *FileStore) Load() (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

func (s *FileStore) load() (Snapshot, error) {
	file, err := os.Open(s.path)
	if err != nil {
		return Snapshot{}, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var snapshot Snapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("decode state: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Snapshot{}, err
	}
	if snapshot.Version != currentVersion {
		return Snapshot{}, fmt.Errorf("unsupported state version %d", snapshot.Version)
	}
	return normalize(snapshot), nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("state contains multiple JSON values")
		}
		return fmt.Errorf("decode trailing state data: %w", err)
	}
	return nil
}

func (s *FileStore) Save(snapshot Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	snapshot.Version = currentVersion
	snapshot.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	snapshot = normalize(snapshot)

	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".shield-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary state: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("secure temporary state: %w", err)
	}
	encoder := json.NewEncoder(tmp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(snapshot); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("encode state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close state: %w", err)
	}

	if runtime.GOOS == "windows" {
		if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("replace old state: %w", err)
		}
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("commit state: %w", err)
	}
	committed = true

	if runtime.GOOS != "windows" {
		dir, err := os.Open(filepath.Dir(s.path))
		if err != nil {
			return fmt.Errorf("open state directory for sync: %w", err)
		}
		syncErr := dir.Sync()
		closeErr := dir.Close()
		if syncErr != nil {
			return fmt.Errorf("sync state directory: %w", syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close state directory: %w", closeErr)
		}
	}
	return nil
}

func normalize(snapshot Snapshot) Snapshot {
	snapshot.Blacklist = uniqueSorted(snapshot.Blacklist)
	snapshot.Whitelist = uniqueSorted(snapshot.Whitelist)
	return snapshot
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// State owns the shared blacklist and whitelist and commits mutations durably.
type State struct {
	cfg       config.Config
	store     *FileStore
	blacklist *blacklist.Manager
	whitelist *whitelist.Manager
	mu        sync.Mutex
}

func NewState(cfg config.Config, store *FileStore) (*State, error) {
	if store == nil {
		return nil, fmt.Errorf("file store is required")
	}
	state := &State{
		cfg:       cfg,
		store:     store,
		blacklist: blacklist.NewManager(),
		whitelist: whitelist.NewManager(),
	}

	snapshot, err := store.Load()
	if errors.Is(err, os.ErrNotExist) {
		if err := store.Save(Snapshot{}); err != nil {
			return nil, fmt.Errorf("initialize state: %w", err)
		}
		return state, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load state: %w", err)
	}
	for _, ip := range snapshot.Whitelist {
		if err := cfg.ValidateIP(ip); err != nil {
			return nil, fmt.Errorf("invalid persisted whitelist entry %q: %w", ip, err)
		}
		if err := state.whitelist.Add(cfg, ip); err != nil {
			return nil, err
		}
	}
	for _, ip := range snapshot.Blacklist {
		if state.whitelist.Contains(ip) {
			return nil, fmt.Errorf("persisted IP %q is both whitelisted and blacklisted", ip)
		}
		if err := cfg.ValidateIP(ip); err != nil {
			return nil, fmt.Errorf("invalid persisted blacklist entry %q: %w", ip, err)
		}
		if err := state.blacklist.Add(cfg, ip); err != nil {
			return nil, err
		}
	}
	return state, nil
}

func (s *State) Blacklist() *blacklist.Manager {
	return s.blacklist
}

func (s *State) Whitelist() *whitelist.Manager {
	return s.whitelist
}

func (s *State) AddBlacklist(ip string) error {
	if err := s.cfg.ValidateIP(ip); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.whitelist.Contains(ip) {
		return fmt.Errorf("IP %s is whitelisted", ip)
	}
	if s.blacklist.Contains(ip) {
		return nil
	}
	snapshot := s.snapshot()
	snapshot.Blacklist = append(snapshot.Blacklist, ip)
	if err := s.store.Save(snapshot); err != nil {
		return err
	}
	return s.blacklist.Add(s.cfg, ip)
}

func (s *State) AddWhitelist(ip string) error {
	if err := s.cfg.ValidateIP(ip); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.blacklist.Contains(ip) {
		return fmt.Errorf("IP %s is blacklisted", ip)
	}
	if s.whitelist.Contains(ip) {
		return nil
	}
	snapshot := s.snapshot()
	snapshot.Whitelist = append(snapshot.Whitelist, ip)
	if err := s.store.Save(snapshot); err != nil {
		return err
	}
	return s.whitelist.Add(s.cfg, ip)
}

func (s *State) RemoveBlacklist(ip string) error {
	if err := s.cfg.ValidateIP(ip); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.blacklist.Contains(ip) {
		return nil
	}
	snapshot := s.snapshot()
	snapshot.Blacklist = without(snapshot.Blacklist, ip)
	if err := s.store.Save(snapshot); err != nil {
		return err
	}
	return s.blacklist.Remove(ip)
}

func (s *State) snapshot() Snapshot {
	return Snapshot{Blacklist: s.blacklist.List(), Whitelist: s.whitelist.List()}
}

func without(values []string, target string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != target {
			result = append(result, value)
		}
	}
	return result
}
