package firewall

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"digitdojo-shield/internal/firewall/backend"
	"digitdojo-shield/internal/firewall/iptables"
	"digitdojo-shield/internal/firewall/nftables"
)

var (
	ErrBackendNotRegistered     = errors.New("firewall backend is not registered")
	ErrBackendAlreadyRegistered = errors.New("firewall backend is already registered")
	ErrBackendNotDetected       = errors.New("firewall backend prerequisites were not detected")
	ErrBackendNotImplemented    = errors.New("firewall backend implementation is not available")
	ErrNoReadyBackend           = errors.New("no detected and implemented firewall backend is available")
	ErrEnforcementDisabled      = errors.New("firewall enforcement is disabled until Linux integration tests pass")
	ErrContextRequired          = errors.New("firewall operation requires a non-nil context")
)

type Registration struct {
	Probe   backend.Probe
	Factory backend.Factory
}

type Registry struct {
	mu      sync.RWMutex
	entries map[backend.Name]Registration
	order   []backend.Name
}

func NewRegistry(registrations ...Registration) (*Registry, error) {
	registry := &Registry{entries: make(map[backend.Name]Registration)}
	for _, registration := range registrations {
		if err := registry.Register(registration); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

// NewDefaultRegistry registers the nftables implementation and detection-only
// iptables support. The Controller's exported constructor still prevents all
// production mutation until the Linux release gate is explicitly opened.
func NewDefaultRegistry() (*Registry, error) {
	locator := backend.ExecLocator{}
	return NewRegistry(
		Registration{Probe: nftables.NewRuntimeProbe(locator), Factory: func() (backend.Backend, error) { return nftables.NewBackend() }},
		Registration{Probe: iptables.NewProbe(locator)},
	)
}

func (r *Registry) Register(registration Registration) error {
	if registration.Probe == nil {
		return fmt.Errorf("firewall backend probe is required")
	}
	name, err := probeNameSafely(registration.Probe)
	if err != nil {
		return err
	}
	if _, err := backend.ParseName(string(name)); err != nil {
		return err
	}
	if name == backend.Auto {
		return fmt.Errorf("auto is reserved for firewall backend selection")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[name]; exists {
		return fmt.Errorf("%w: %s", ErrBackendAlreadyRegistered, name)
	}
	r.entries[name] = registration
	r.order = append(r.order, name)
	return nil
}

func (r *Registry) Has(name backend.Name) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.entries[name]
	return exists
}

func (r *Registry) Detect(ctx context.Context) []backend.Capability {
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.RLock()
	type namedRegistration struct {
		name         backend.Name
		registration Registration
	}
	entries := make([]namedRegistration, 0, len(r.order))
	for _, name := range r.order {
		entries = append(entries, namedRegistration{name: name, registration: r.entries[name]})
	}
	r.mu.RUnlock()

	capabilities := make([]backend.Capability, 0, len(entries))
	for _, entry := range entries {
		capability := detectSafely(entry.name, entry.registration.Probe, ctx)
		capability.Name = entry.name
		capability.Implemented = entry.registration.Factory != nil
		capability.Commands = cloneMap(capability.Commands)
		capability.Missing = append([]string(nil), capability.Missing...)
		capabilities = append(capabilities, capability)
	}
	return capabilities
}

func (r *Registry) Resolve(ctx context.Context, requested backend.Name) (backend.Backend, error) {
	if ctx == nil {
		return nil, ErrContextRequired
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if requested == backend.Auto {
		for _, capability := range r.Detect(ctx) {
			if capability.Detected && capability.Implemented {
				return r.instantiate(capability.Name)
			}
		}
		return nil, ErrNoReadyBackend
	}

	r.mu.RLock()
	registration, exists := r.entries[requested]
	r.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrBackendNotRegistered, requested)
	}
	capability := detectSafely(requested, registration.Probe, ctx)
	if !capability.Detected {
		return nil, fmt.Errorf("%w: %s: %s", ErrBackendNotDetected, requested, capability.Reason)
	}
	if registration.Factory == nil {
		return nil, fmt.Errorf("%w: %s", ErrBackendNotImplemented, requested)
	}
	return r.instantiate(requested)
}

func (r *Registry) instantiate(name backend.Name) (implementation backend.Backend, err error) {
	r.mu.RLock()
	registration, exists := r.entries[name]
	r.mu.RUnlock()
	if !exists || registration.Factory == nil {
		return nil, fmt.Errorf("%w: %s", ErrBackendNotImplemented, name)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			implementation = nil
			err = fmt.Errorf("create firewall backend %s: factory panic: %v", name, recovered)
		}
	}()
	implementation, err = registration.Factory()
	if err != nil {
		return nil, fmt.Errorf("create firewall backend %s: %w", name, err)
	}
	if implementation == nil {
		return nil, fmt.Errorf("create firewall backend %s: factory returned nil", name)
	}
	if implementation.Name() != name {
		return nil, fmt.Errorf("firewall backend factory registered as %s returned %s", name, implementation.Name())
	}
	return implementation, nil
}

func probeNameSafely(probe backend.Probe) (name backend.Name, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			name = ""
			err = fmt.Errorf("firewall backend probe name panic: %v", recovered)
		}
	}()
	return probe.Name(), nil
}

func detectSafely(name backend.Name, probe backend.Probe, ctx context.Context) (capability backend.Capability) {
	capability.Name = name
	defer func() {
		if recovered := recover(); recovered != nil {
			capability = backend.Capability{Name: name, Reason: fmt.Sprintf("capability probe panic: %v", recovered)}
		}
	}()
	return probe.Detect(ctx)
}

func (r *Registry) Describe(ctx context.Context, selected backend.Name) string {
	capabilities := r.Detect(ctx)
	parts := []string{"selected=" + string(selected), "enforcement=disabled"}
	for _, capability := range capabilities {
		status := "missing"
		if capability.Detected {
			status = "detected"
		}
		if capability.Detected && capability.Implemented {
			status = "implemented"
		}
		parts = append(parts, fmt.Sprintf("%s=%s", capability.Name, status))
	}
	sort.Strings(parts[2:])
	return strings.Join(parts, " ")
}

func cloneMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}
