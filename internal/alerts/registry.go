package alerts

import (
	"fmt"
	"sync"
)

// Registry resolves provider-neutral transports by persisted provider type.
type Registry struct {
	mu    sync.RWMutex
	items map[ProviderType]Transport
}

func NewRegistry() *Registry { return &Registry{items: map[ProviderType]Transport{}} }
func (r *Registry) Register(kind ProviderType, transport Transport) error {
	if kind == "" || transport == nil {
		return fmt.Errorf("provider type and transport are required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[kind]; exists {
		return fmt.Errorf("provider %s already registered", kind)
	}
	r.items[kind] = transport
	return nil
}
func (r *Registry) Resolve(kind ProviderType) (Transport, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	transport, ok := r.items[kind]
	return transport, ok
}
