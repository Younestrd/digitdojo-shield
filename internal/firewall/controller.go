package firewall

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"digitdojo-shield/internal/firewall/backend"
)

const rollbackTimeout = 15 * time.Second

// Controller serializes privileged backend operations and owns rollback.
// The exported constructor always keeps enforcement disabled.
type Controller struct {
	registry *Registry
	selected backend.Name
	enabled  bool
	mu       sync.Mutex
}

func NewController(registry *Registry, selection string) (*Controller, error) {
	return newController(registry, selection, false)
}

func newController(registry *Registry, selection string, enabled bool) (*Controller, error) {
	if registry == nil {
		return nil, fmt.Errorf("firewall backend registry is required")
	}
	selected, err := backend.ParseName(selection)
	if err != nil {
		return nil, err
	}
	if selected != backend.Auto && !registry.Has(selected) {
		return nil, fmt.Errorf("%w: %s", ErrBackendNotRegistered, selected)
	}
	return &Controller{registry: registry, selected: selected, enabled: enabled}, nil
}

func (c *Controller) EnforcementEnabled() bool {
	return c.enabled
}

func (c *Controller) Selected() backend.Name {
	return c.selected
}

func (c *Controller) Capabilities(ctx context.Context) []backend.Capability {
	return c.registry.Detect(ctx)
}

func (c *Controller) Describe(ctx context.Context) string {
	return c.registry.Describe(ctx, c.selected)
}

func (c *Controller) Reconcile(ctx context.Context, desired backend.DesiredState) error {
	if !c.enabled {
		return ErrEnforcementDisabled
	}
	if ctx == nil {
		return ErrContextRequired
	}
	normalized, err := desired.Normalize(time.Now().UTC())
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	implementation, err := c.registry.Resolve(ctx, c.selected)
	if err != nil {
		return err
	}
	return c.executeWithRollback(ctx, implementation, func() error {
		return implementation.Reconcile(ctx, normalized)
	})
}

func (c *Controller) Cleanup(ctx context.Context) error {
	if !c.enabled {
		return ErrEnforcementDisabled
	}
	if ctx == nil {
		return ErrContextRequired
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	implementation, err := c.registry.Resolve(ctx, c.selected)
	if err != nil {
		return err
	}
	return c.executeWithRollback(ctx, implementation, func() error {
		return implementation.Cleanup(ctx)
	})
}

func (c *Controller) Inspect(ctx context.Context) (backend.DesiredState, error) {
	if ctx == nil {
		return backend.DesiredState{}, ErrContextRequired
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	implementation, err := c.registry.Resolve(ctx, c.selected)
	if err != nil {
		return backend.DesiredState{}, err
	}
	return inspectSafely(implementation, ctx)
}

func (c *Controller) executeWithRollback(ctx context.Context, implementation backend.Backend, operation func() error) (err error) {
	name, err := backendNameSafely(implementation)
	if err != nil {
		return err
	}
	snapshot, err := snapshotSafely(implementation, ctx)
	if err != nil {
		return fmt.Errorf("snapshot Shield-managed firewall state: %w", err)
	}
	if snapshot.Backend != name {
		return fmt.Errorf("firewall snapshot backend mismatch: got %s, expected %s", snapshot.Backend, name)
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("firewall backend panic: %v", recovered)
		}
		if err == nil {
			return
		}
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
		defer cancel()
		if rollbackErr := restoreSafely(implementation, rollbackCtx, snapshot); rollbackErr != nil {
			err = errors.Join(err, fmt.Errorf("restore Shield-managed firewall state: %w", rollbackErr))
		}
	}()

	err = operation()
	return err
}

func backendNameSafely(implementation backend.Backend) (name backend.Name, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			name = ""
			err = fmt.Errorf("firewall backend name panic: %v", recovered)
		}
	}()
	return implementation.Name(), nil
}

func snapshotSafely(implementation backend.Backend, ctx context.Context) (snapshot backend.Snapshot, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("backend snapshot panic: %v", recovered)
		}
	}()
	return implementation.Snapshot(ctx)
}

func restoreSafely(implementation backend.Backend, ctx context.Context, snapshot backend.Snapshot) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("backend restore panic: %v", recovered)
		}
	}()
	return implementation.Restore(ctx, snapshot)
}

func inspectSafely(implementation backend.Backend, ctx context.Context) (state backend.DesiredState, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("backend inspect panic: %v", recovered)
		}
	}()
	return implementation.Inspect(ctx)
}
