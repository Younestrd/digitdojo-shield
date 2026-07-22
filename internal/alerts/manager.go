package alerts

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type ProviderType string

const (
	Discord  ProviderType = "discord"
	Slack    ProviderType = "slack"
	SMTP     ProviderType = "smtp"
	Webhook  ProviderType = "webhook"
	Telegram ProviderType = "telegram"
)

type RetryPolicy struct {
	Attempts             int `json:"attempts"`
	InitialBackoffMillis int `json:"initial_backoff_millis"`
}
type Provider struct {
	ID            string          `json:"id"`
	Type          ProviderType    `json:"type"`
	Name          string          `json:"name"`
	Enabled       bool            `json:"enabled"`
	Secret        json.RawMessage `json:"secret"`
	Retry         RetryPolicy     `json:"retry"`
	TimeoutMillis int             `json:"timeout_millis"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	Validation    string          `json:"validation"`
}
type Rule struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Enabled         bool              `json:"enabled"`
	EventType       string            `json:"event_type"`
	MinimumSeverity string            `json:"minimum_severity"`
	ProviderIDs     []string          `json:"provider_ids"`
	CooldownSeconds int               `json:"cooldown_seconds"`
	Conditions      map[string]string `json:"conditions"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}
type Delivery struct {
	ID             string    `json:"id"`
	RuleID         string    `json:"rule_id"`
	ProviderID     string    `json:"provider_id"`
	Event          string    `json:"event"`
	Severity       string    `json:"severity"`
	Timestamp      time.Time `json:"timestamp"`
	Result         string    `json:"result"`
	DurationMillis int64     `json:"duration_millis"`
	Error          string    `json:"error,omitempty"`
}
type state struct {
	Version    int        `json:"version"`
	Providers  []Provider `json:"providers"`
	Rules      []Rule     `json:"rules"`
	Deliveries []Delivery `json:"deliveries"`
}
type Manager struct {
	mu         sync.RWMutex
	path       string
	state      state
	transports map[ProviderType]Transport
	cooldowns  map[string]time.Time
}
type Event struct {
	Type     string
	Severity string
	Message  string
	Fields   map[string]string
}
type Transport interface {
	Validate(context.Context, json.RawMessage) error
	Send(context.Context, json.RawMessage, string) error
}

func NewManager(path string, transports map[ProviderType]Transport) (*Manager, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	m := &Manager{path: path, transports: transports, cooldowns: map[string]time.Time{}, state: state{Version: 1}}
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &m.state); err != nil {
			return nil, fmt.Errorf("decode alert state: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := m.saveLocked(); err != nil {
		return nil, err
	}
	return m, nil
}
func (m *Manager) AddProvider(provider Provider) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if provider.ID == "" {
		provider.ID = id()
	}
	if provider.Name == "" || m.transports[provider.Type] == nil {
		return fmt.Errorf("provider name and supported type are required")
	}
	if provider.TimeoutMillis <= 0 {
		provider.TimeoutMillis = 10000
	}
	if provider.Retry.Attempts <= 0 {
		provider.Retry.Attempts = 3
	}
	now := time.Now().UTC()
	provider.CreatedAt, provider.UpdatedAt = now, now
	m.state.Providers = append(m.state.Providers, provider)
	return m.saveLocked()
}
func (m *Manager) Dispatch(ctx context.Context, event Event) {
	m.mu.RLock()
	rules := append([]Rule(nil), m.state.Rules...)
	providers := append([]Provider(nil), m.state.Providers...)
	m.mu.RUnlock()
	for _, rule := range rules {
		if !rule.Enabled || rule.EventType != event.Type {
			continue
		}
		key := rule.ID + event.Type
		m.mu.Lock()
		if until := m.cooldowns[key]; until.After(time.Now()) {
			m.mu.Unlock()
			continue
		}
		m.cooldowns[key] = time.Now().Add(time.Duration(rule.CooldownSeconds) * time.Second)
		m.mu.Unlock()
		for _, pid := range rule.ProviderIDs {
			for _, provider := range providers {
				if provider.ID == pid && provider.Enabled {
					m.deliver(ctx, rule, provider, event)
				}
			}
		}
	}
}
func (m *Manager) deliver(ctx context.Context, rule Rule, provider Provider, event Event) {
	start := time.Now()
	delivery := Delivery{ID: id(), RuleID: rule.ID, ProviderID: provider.ID, Event: event.Type, Severity: event.Severity, Timestamp: start, Result: "failed"}
	transport := m.transports[provider.Type]
	timeout := time.Duration(provider.TimeoutMillis) * time.Millisecond
	attempts := provider.Retry.Attempts
	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, timeout)
		err = transport.Send(attemptCtx, provider.Secret, event.Message)
		cancel()
		if err == nil {
			delivery.Result = "delivered"
			break
		}
		if attempt+1 < attempts {
			select {
			case <-ctx.Done():
				break
			case <-time.After(time.Duration(provider.Retry.InitialBackoffMillis*(1<<attempt)) * time.Millisecond):
			}
		}
	}
	delivery.DurationMillis = time.Since(start).Milliseconds()
	if err != nil {
		delivery.Error = err.Error()
	}
	m.mu.Lock()
	m.state.Deliveries = append(m.state.Deliveries, delivery)
	if len(m.state.Deliveries) > 10000 {
		m.state.Deliveries = m.state.Deliveries[len(m.state.Deliveries)-10000:]
	}
	_ = m.saveLocked()
	m.mu.Unlock()
}
func (m *Manager) saveLocked() error {
	data, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(m.path), ".alerts-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, m.path)
}
func id() string {
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
