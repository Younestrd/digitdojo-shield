package firewall

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"digitdojo-shield/internal/firewall/backend"
)

type testProbe struct {
	name      backend.Name
	detected  bool
	panic     bool
	panicName bool
}

func (p testProbe) Name() backend.Name {
	if p.panicName {
		panic("probe name panic")
	}
	return p.name
}

func (p testProbe) Detect(ctx context.Context) backend.Capability {
	if p.panic {
		panic("probe panic")
	}
	if err := ctx.Err(); err != nil {
		return backend.Capability{Name: p.name, Reason: err.Error()}
	}
	return backend.Capability{Name: p.name, Detected: p.detected}
}

type testBackend struct {
	name backend.Name

	mu                  sync.Mutex
	snapshot            backend.Snapshot
	snapshotErr         error
	reconcileErr        error
	restoreErr          error
	cleanupErr          error
	panicOnApply        bool
	panicSnapshot       bool
	panicRestore        bool
	panicInspect        bool
	panicNameAfterFirst bool
	nameCalls           atomic.Int32
	onApply             func()
	restoreCtxErr       error
	snapshotCalls       int
	applyCalls          int
	restoreCalls        int
	cleanupCalls        int
	desired             backend.DesiredState
}

type serialBackend struct {
	entered chan struct{}
	release chan struct{}
}

func (b *serialBackend) Name() backend.Name { return "serial" }

func (b *serialBackend) Snapshot(context.Context) (backend.Snapshot, error) {
	return backend.Snapshot{Backend: "serial"}, nil
}

func (b *serialBackend) Reconcile(context.Context, backend.DesiredState) error {
	b.entered <- struct{}{}
	<-b.release
	return nil
}

func (b *serialBackend) Inspect(context.Context) (backend.DesiredState, error) {
	return backend.DesiredState{}, nil
}

func (b *serialBackend) Restore(context.Context, backend.Snapshot) error { return nil }

func (b *serialBackend) Cleanup(context.Context) error { return nil }

func (b *testBackend) Name() backend.Name {
	if b.panicNameAfterFirst && b.nameCalls.Add(1) > 1 {
		panic("backend name panic")
	}
	return b.name
}

func (b *testBackend) Snapshot(context.Context) (backend.Snapshot, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.snapshotCalls++
	if b.panicSnapshot {
		panic("snapshot panic")
	}
	return b.snapshot, b.snapshotErr
}

func (b *testBackend) Reconcile(_ context.Context, desired backend.DesiredState) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.applyCalls++
	b.desired = desired
	if b.onApply != nil {
		b.onApply()
	}
	if b.panicOnApply {
		panic("apply panic")
	}
	return b.reconcileErr
}

func (b *testBackend) Inspect(context.Context) (backend.DesiredState, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.panicInspect {
		panic("inspect panic")
	}
	return b.desired, nil
}

func (b *testBackend) Restore(ctx context.Context, _ backend.Snapshot) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.restoreCalls++
	b.restoreCtxErr = ctx.Err()
	if b.panicRestore {
		panic("restore panic")
	}
	return b.restoreErr
}

func (b *testBackend) Cleanup(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cleanupCalls++
	return b.cleanupErr
}

func registration(name backend.Name, detected bool, implementation *testBackend) Registration {
	result := Registration{Probe: testProbe{name: name, detected: detected}}
	if implementation != nil {
		result.Factory = func() (backend.Backend, error) { return implementation, nil }
	}
	return result
}

func TestRegistryRejectsInvalidAndDuplicateRegistrations(t *testing.T) {
	if _, err := NewRegistry(Registration{}); err == nil {
		t.Fatalf("expected nil probe to fail")
	}
	probe := testProbe{name: "mock", detected: true}
	_, err := NewRegistry(Registration{Probe: probe}, Registration{Probe: probe})
	if !errors.Is(err, ErrBackendAlreadyRegistered) {
		t.Fatalf("expected duplicate error, got %v", err)
	}
	if _, err := NewRegistry(Registration{Probe: testProbe{name: backend.Auto}}); err == nil {
		t.Fatalf("expected reserved auto registration to fail")
	}
	if _, err := NewRegistry(Registration{Probe: testProbe{panicName: true}}); err == nil || !strings.Contains(err.Error(), "probe name panic") {
		t.Fatalf("expected probe name panic to be contained, got %v", err)
	}
}

func TestRegistryRejectsNilResolveContext(t *testing.T) {
	registry, err := NewRegistry(registration("mock", true, &testBackend{name: "mock"}))
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	if _, err := registry.Resolve(nil, "mock"); !errors.Is(err, ErrContextRequired) {
		t.Fatalf("expected context error, got %v", err)
	}
	capabilities := registry.Detect(nil)
	if len(capabilities) != 1 || !capabilities[0].Detected {
		t.Fatalf("nil-context detection should use a background context: %+v", capabilities)
	}
}

func TestRegistryDetectionSeparatesInstalledAndImplemented(t *testing.T) {
	implementation := &testBackend{name: "ready"}
	registry, err := NewRegistry(
		registration("detected_only", true, nil),
		registration("ready", true, implementation),
	)
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	capabilities := registry.Detect(context.Background())
	if len(capabilities) != 2 || !capabilities[0].Detected || capabilities[0].Implemented || !capabilities[1].Implemented {
		t.Fatalf("unexpected capabilities: %+v", capabilities)
	}
	resolved, err := registry.Resolve(context.Background(), backend.Auto)
	if err != nil || resolved != implementation {
		t.Fatalf("auto resolution failed: backend=%v error=%v", resolved, err)
	}
	if _, err := registry.Resolve(context.Background(), "detected_only"); !errors.Is(err, ErrBackendNotImplemented) {
		t.Fatalf("expected unimplemented error, got %v", err)
	}
}

func TestDefaultRegistryReportsOnlyNFTablesAsImplemented(t *testing.T) {
	registry, err := NewDefaultRegistry()
	if err != nil {
		t.Fatalf("create default registry: %v", err)
	}
	for _, capability := range registry.Detect(context.Background()) {
		if capability.Name == backend.NFTables && !capability.Implemented {
			t.Fatalf("nftables implementation was not registered")
		}
		if capability.Name == backend.IPTables && capability.Implemented {
			t.Fatalf("iptables unexpectedly reports an implementation")
		}
	}
	controller, err := NewController(registry, "auto")
	if err != nil {
		t.Fatalf("create default controller: %v", err)
	}
	if controller.EnforcementEnabled() {
		t.Fatalf("registering the implementation must not enable enforcement")
	}
}

func TestControllerExportedConstructorKeepsEnforcementDisabled(t *testing.T) {
	created := 0
	registry, err := NewRegistry(Registration{
		Probe: testProbe{name: "mock", detected: true},
		Factory: func() (backend.Backend, error) {
			created++
			return &testBackend{name: "mock"}, nil
		},
	})
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	controller, err := NewController(registry, "mock")
	if err != nil {
		t.Fatalf("create controller: %v", err)
	}
	if controller.EnforcementEnabled() {
		t.Fatalf("exported controller must not enable enforcement")
	}
	if err := controller.Reconcile(context.Background(), backend.DesiredState{}); !errors.Is(err, ErrEnforcementDisabled) {
		t.Fatalf("expected enforcement guard, got %v", err)
	}
	if err := controller.Cleanup(context.Background()); !errors.Is(err, ErrEnforcementDisabled) {
		t.Fatalf("expected cleanup guard, got %v", err)
	}
	if created != 0 {
		t.Fatalf("disabled controller instantiated a privileged backend")
	}
}

func TestControllerRejectsUnregisteredSelection(t *testing.T) {
	registry, err := NewRegistry()
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	if _, err := NewController(registry, "unknown"); !errors.Is(err, ErrBackendNotRegistered) {
		t.Fatalf("expected unregistered selection error, got %v", err)
	}
}

func TestControllerNormalizesAndReconciles(t *testing.T) {
	implementation := &testBackend{name: "mock", snapshot: backend.Snapshot{Backend: "mock", Data: []byte("before")}}
	controller := enabledController(t, implementation)
	desired := backend.DesiredState{PermanentBans: []netip.Addr{
		netip.MustParseAddr("2001:db8::2"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("192.0.2.2"),
	}}
	if err := controller.Reconcile(context.Background(), desired); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if implementation.snapshotCalls != 1 || implementation.applyCalls != 1 || implementation.restoreCalls != 0 {
		t.Fatalf("unexpected calls: %+v", implementation)
	}
	if len(implementation.desired.PermanentBans) != 2 || !implementation.desired.PermanentBans[0].Is4() || !implementation.desired.PermanentBans[1].Is6() {
		t.Fatalf("desired state was not normalized: %+v", implementation.desired)
	}
}

func TestControllerRollsBackErrorsAndPanics(t *testing.T) {
	tests := []struct {
		name            string
		configure       func(*testBackend)
		expectedMessage string
	}{
		{name: "reconcile error", configure: func(b *testBackend) { b.reconcileErr = errors.New("apply failed") }, expectedMessage: "apply failed"},
		{name: "panic", configure: func(b *testBackend) { b.panicOnApply = true }, expectedMessage: "apply panic"},
		{name: "rollback error", configure: func(b *testBackend) {
			b.reconcileErr = errors.New("apply failed")
			b.restoreErr = errors.New("rollback failed")
		}, expectedMessage: "rollback failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			implementation := &testBackend{name: "mock", snapshot: backend.Snapshot{Backend: "mock"}}
			test.configure(implementation)
			controller := enabledController(t, implementation)
			err := controller.Reconcile(context.Background(), backend.DesiredState{})
			if err == nil || !strings.Contains(err.Error(), test.expectedMessage) {
				t.Fatalf("unexpected error: %v", err)
			}
			if implementation.restoreCalls != 1 {
				t.Fatalf("expected one rollback, got %d", implementation.restoreCalls)
			}
		})
	}
}

func TestControllerCleanupRollsBackAndSnapshotFailureDoesNotRestore(t *testing.T) {
	t.Run("cleanup failure", func(t *testing.T) {
		implementation := &testBackend{
			name:       "mock",
			snapshot:   backend.Snapshot{Backend: "mock"},
			cleanupErr: errors.New("cleanup failed"),
		}
		controller := enabledController(t, implementation)
		if err := controller.Cleanup(context.Background()); err == nil || !strings.Contains(err.Error(), "cleanup failed") {
			t.Fatalf("unexpected cleanup error: %v", err)
		}
		if implementation.cleanupCalls != 1 || implementation.restoreCalls != 1 {
			t.Fatalf("cleanup was not rolled back: cleanup=%d restore=%d", implementation.cleanupCalls, implementation.restoreCalls)
		}
	})
	t.Run("snapshot failure", func(t *testing.T) {
		implementation := &testBackend{name: "mock", snapshotErr: errors.New("snapshot failed")}
		controller := enabledController(t, implementation)
		if err := controller.Reconcile(context.Background(), backend.DesiredState{}); err == nil || !strings.Contains(err.Error(), "snapshot failed") {
			t.Fatalf("unexpected snapshot error: %v", err)
		}
		if implementation.applyCalls != 0 || implementation.restoreCalls != 0 {
			t.Fatalf("snapshot failure should not mutate: apply=%d restore=%d", implementation.applyCalls, implementation.restoreCalls)
		}
	})
}

func TestControllerRollbackSurvivesCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	implementation := &testBackend{
		name:         "mock",
		snapshot:     backend.Snapshot{Backend: "mock"},
		reconcileErr: errors.New("apply failed"),
		onApply:      cancel,
	}
	controller := enabledController(t, implementation)
	if err := controller.Reconcile(ctx, backend.DesiredState{}); err == nil {
		t.Fatalf("expected reconcile failure")
	}
	if implementation.restoreCalls != 1 || implementation.restoreCtxErr != nil {
		t.Fatalf("rollback did not receive an independent context: calls=%d context_error=%v", implementation.restoreCalls, implementation.restoreCtxErr)
	}
}

func TestControllerRejectsMismatchedSnapshotBeforeMutation(t *testing.T) {
	implementation := &testBackend{name: "mock", snapshot: backend.Snapshot{Backend: "other"}}
	controller := enabledController(t, implementation)
	err := controller.Reconcile(context.Background(), backend.DesiredState{})
	if err == nil || !strings.Contains(err.Error(), "snapshot backend mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
	if implementation.applyCalls != 0 || implementation.restoreCalls != 0 {
		t.Fatalf("mismatched snapshot must not mutate or restore")
	}
}

func TestRegistryRejectsFactoryNameMismatch(t *testing.T) {
	registry, err := NewRegistry(Registration{
		Probe:   testProbe{name: "registered", detected: true},
		Factory: func() (backend.Backend, error) { return &testBackend{name: "wrong"}, nil },
	})
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	if _, err := registry.Resolve(context.Background(), "registered"); err == nil || !strings.Contains(err.Error(), "returned wrong") {
		t.Fatalf("expected factory mismatch, got %v", err)
	}
}

func TestRegistryContainsProbeAndFactoryPanics(t *testing.T) {
	registry, err := NewRegistry(
		Registration{Probe: testProbe{name: "probe_panic", panic: true}},
		Registration{
			Probe: testProbe{name: "factory_panic", detected: true},
			Factory: func() (backend.Backend, error) {
				panic("factory panic")
			},
		},
	)
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	capabilities := registry.Detect(context.Background())
	if capabilities[0].Detected || !strings.Contains(capabilities[0].Reason, "probe panic") {
		t.Fatalf("probe panic was not contained: %+v", capabilities[0])
	}
	if _, err := registry.Resolve(context.Background(), "factory_panic"); err == nil || !strings.Contains(err.Error(), "factory panic") {
		t.Fatalf("factory panic was not contained: %v", err)
	}
}

func TestControllerContainsSnapshotRestoreAndInspectPanics(t *testing.T) {
	t.Run("name", func(t *testing.T) {
		implementation := &testBackend{
			name:                "mock",
			panicNameAfterFirst: true,
			snapshot:            backend.Snapshot{Backend: "mock"},
		}
		controller := enabledController(t, implementation)
		err := controller.Reconcile(context.Background(), backend.DesiredState{})
		if err == nil || !strings.Contains(err.Error(), "backend name panic") {
			t.Fatalf("backend name panic was not contained: %v", err)
		}
		if implementation.snapshotCalls != 0 || implementation.applyCalls != 0 || implementation.restoreCalls != 0 {
			t.Fatalf("backend name panic must not access or mutate firewall state")
		}
	})
	t.Run("snapshot", func(t *testing.T) {
		implementation := &testBackend{name: "mock", panicSnapshot: true}
		controller := enabledController(t, implementation)
		err := controller.Reconcile(context.Background(), backend.DesiredState{})
		if err == nil || !strings.Contains(err.Error(), "snapshot panic") || implementation.applyCalls != 0 {
			t.Fatalf("snapshot panic was not contained: error=%v apply_calls=%d", err, implementation.applyCalls)
		}
	})
	t.Run("restore", func(t *testing.T) {
		implementation := &testBackend{
			name:         "mock",
			snapshot:     backend.Snapshot{Backend: "mock"},
			reconcileErr: errors.New("apply failed"),
			panicRestore: true,
		}
		controller := enabledController(t, implementation)
		err := controller.Reconcile(context.Background(), backend.DesiredState{})
		if err == nil || !strings.Contains(err.Error(), "restore panic") {
			t.Fatalf("restore panic was not contained: %v", err)
		}
	})
	t.Run("inspect", func(t *testing.T) {
		implementation := &testBackend{name: "mock", panicInspect: true}
		controller := enabledController(t, implementation)
		if _, err := controller.Inspect(context.Background()); err == nil || !strings.Contains(err.Error(), "inspect panic") {
			t.Fatalf("inspect panic was not contained: %v", err)
		}
	})
}

func TestControllerRequiresContextWhenEnabled(t *testing.T) {
	implementation := &testBackend{name: "mock"}
	controller := enabledController(t, implementation)
	if err := controller.Reconcile(nil, backend.DesiredState{}); !errors.Is(err, ErrContextRequired) {
		t.Fatalf("expected reconcile context error, got %v", err)
	}
	if err := controller.Cleanup(nil); !errors.Is(err, ErrContextRequired) {
		t.Fatalf("expected cleanup context error, got %v", err)
	}
	if _, err := controller.Inspect(nil); !errors.Is(err, ErrContextRequired) {
		t.Fatalf("expected inspect context error, got %v", err)
	}
}

func TestControllerSerializesBackendMutations(t *testing.T) {
	implementation := &serialBackend{entered: make(chan struct{}), release: make(chan struct{})}
	registry, err := NewRegistry(Registration{
		Probe:   testProbe{name: "serial", detected: true},
		Factory: func() (backend.Backend, error) { return implementation, nil },
	})
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	controller, err := newController(registry, "serial", true)
	if err != nil {
		t.Fatalf("create controller: %v", err)
	}

	results := make(chan error, 2)
	go func() { results <- controller.Reconcile(context.Background(), backend.DesiredState{}) }()
	<-implementation.entered
	go func() { results <- controller.Reconcile(context.Background(), backend.DesiredState{}) }()

	select {
	case <-implementation.entered:
		implementation.release <- struct{}{}
		implementation.release <- struct{}{}
		<-results
		<-results
		t.Fatalf("second backend mutation entered before the first completed")
	case <-time.After(100 * time.Millisecond):
	}

	implementation.release <- struct{}{}
	if err := <-results; err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	select {
	case <-implementation.entered:
	case <-time.After(time.Second):
		t.Fatalf("second backend mutation did not start after the first completed")
	}
	implementation.release <- struct{}{}
	if err := <-results; err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
}

func enabledController(t *testing.T, implementation *testBackend) *Controller {
	t.Helper()
	registry, err := NewRegistry(registration(implementation.name, true, implementation))
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	controller, err := newController(registry, string(implementation.name), true)
	if err != nil {
		t.Fatalf("create controller: %v", err)
	}
	return controller
}
