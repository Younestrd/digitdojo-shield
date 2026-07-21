package whitelist

import (
    "fmt"
    "sync"

    "digitdojo-shield/internal/config"
)

type Manager struct {
    mu    sync.RWMutex
    items map[string]struct{}
}

func NewManager() *Manager {
    return &Manager{items: make(map[string]struct{})}
}

func (m *Manager) Add(cfg config.Config, ip string) error {
    if err := cfg.ValidateIP(ip); err != nil {
        return err
    }
    m.mu.Lock()
    defer m.mu.Unlock()
    m.items[ip] = struct{}{}
    return nil
}

func (m *Manager) Remove(ip string) error {
    if ip == "" {
        return fmt.Errorf("ip cannot be empty")
    }
    m.mu.Lock()
    defer m.mu.Unlock()
    delete(m.items, ip)
    return nil
}

func (m *Manager) Contains(ip string) bool {
    m.mu.RLock()
    defer m.mu.RUnlock()
    _, ok := m.items[ip]
    return ok
}

func (m *Manager) List() []string {
    m.mu.RLock()
    defer m.mu.RUnlock()
    out := make([]string, 0, len(m.items))
    for ip := range m.items {
        out = append(out, ip)
    }
    return out
}
