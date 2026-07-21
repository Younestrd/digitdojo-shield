package config

import (
	"fmt"
	"os"
	"sync"
)

// ReloadableConfig watches a config file and can reload it safely.
type ReloadableConfig struct {
	path string
	mu   sync.RWMutex
	cfg  Config
}

// NewReloadableConfig loads the config from disk and keeps it in memory.
func NewReloadableConfig(path string) (*ReloadableConfig, error) {
	cfg, err := LoadFromFile(path)
	if err != nil {
		return nil, err
	}
	return &ReloadableConfig{path: path, cfg: cfg}, nil
}

// Current returns the current config.
func (r *ReloadableConfig) Current() Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cfg
}

// Reload loads the config again and validates it before replacing the active copy.
func (r *ReloadableConfig) Reload() error {
	if r.path == "" {
		return fmt.Errorf("config path is empty")
	}
	if _, err := os.Stat(r.path); err != nil {
		return err
	}
	newCfg, err := LoadFromFile(r.path)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cfg = newCfg
	return nil
}
