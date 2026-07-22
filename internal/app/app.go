package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"digitdojo-shield/internal/alerts"
	"digitdojo-shield/internal/api"
	"digitdojo-shield/internal/config"
	"digitdojo-shield/internal/detector"
	"digitdojo-shield/internal/events"
	"digitdojo-shield/internal/firewall"
	"digitdojo-shield/internal/history"
	"digitdojo-shield/internal/logger"
	"digitdojo-shield/internal/monitor"
	"digitdojo-shield/internal/storage"
)

const (
	eventRuntimeStarted  = "RuntimeStarted"
	eventRuntimeStopped  = "RuntimeStopped"
	eventSampleCollected = "SampleCollected"
	eventAttackDetected  = "AttackDetected"
	eventAttackCleared   = "AttackCleared"
	eventRuntimeError    = "RuntimeError"
)

// Application owns every daemon subsystem and their shared lifecycle.
type Application struct {
	cfg      config.Config
	logger   *logger.StructuredLogger
	firewall *firewall.Controller
	storage  *storage.State
	history  *history.Store
	detector *detector.Daemon
	engine   *detector.Engine
	monitor  *monitor.Monitor
	events   *events.Bus
	alerts   *alerts.Service
	api      *api.Server

	statsMu sync.RWMutex
	stats   api.RuntimeStats
	runCtx  context.Context

	lifecycleMu sync.Mutex
	runCalled   bool
	ready       chan struct{}
}

// New constructs the complete runtime without starting background work.
func New(cfg config.Config) (*Application, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate configuration: %w", err)
	}
	if err := prepareDirectory(cfg.General.LogDir, 0o750); err != nil {
		return nil, fmt.Errorf("prepare log directory: %w", err)
	}
	if err := prepareDirectory(cfg.General.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("prepare state directory: %w", err)
	}

	log, err := logger.NewStructuredLogger(filepath.Join(cfg.General.LogDir, "shieldd.json.log"), true)
	if err != nil {
		return nil, fmt.Errorf("initialize logger: %w", err)
	}
	fail := func(cause error) (*Application, error) {
		_ = log.Close()
		return nil, cause
	}

	alertService := alerts.New(cfg.Alerts.DiscordWebhook, cfg.Alerts.SlackWebhook, cfg.Alerts.Email)
	if err := alertService.Validate(); err != nil {
		return fail(fmt.Errorf("validate alerts: %w", err))
	}
	fileStore, err := storage.NewFileStore(filepath.Join(cfg.General.StateDir, "shield-state.json"))
	if err != nil {
		return fail(fmt.Errorf("initialize persistent storage: %w", err))
	}
	sharedState, err := storage.NewState(cfg, fileStore)
	if err != nil {
		return fail(fmt.Errorf("initialize shared state: %w", err))
	}
	historyStore, err := history.New(filepath.Join(cfg.General.StateDir, "shield-history.json"))
	if err != nil {
		return fail(fmt.Errorf("initialize telemetry history: %w", err))
	}
	backendRegistry, err := firewall.NewDefaultRegistry()
	if err != nil {
		return fail(fmt.Errorf("initialize firewall backend registry: %w", err))
	}
	firewallController, err := firewall.NewController(backendRegistry, cfg.Firewall.Backend)
	if err != nil {
		return fail(fmt.Errorf("initialize firewall controller: %w", err))
	}

	application := &Application{
		cfg:      cfg,
		logger:   log,
		firewall: firewallController,
		storage:  sharedState,
		history:  historyStore,
		detector: detector.NewDaemon(time.Duration(cfg.Detection.WindowSeconds) * time.Second),
		engine:   detector.NewEngine(cfg.Detection.PacketThreshold),
		monitor:  monitor.New(),
		events:   events.NewBus(),
		alerts:   alertService,
		ready:    make(chan struct{}),
	}
	application.stats = api.RuntimeStats{
		AttackStatus:    "starting",
		FirewallBackend: application.firewall.Describe(context.Background()),
		Blocked:         sharedState.Blacklist().ListLen(),
	}

	apiServer, err := api.NewServerWithDependencies(cfg, api.Dependencies{
		Blacklist: sharedState.Blacklist(),
		Whitelist: sharedState.Whitelist(),
		Stats:     application.Stats,
		AddBlacklist: func(string) error {
			return fmt.Errorf("%w: blacklist changes are disabled until the privileged Linux firewall integration gate passes", api.ErrEnforcementUnavailable)
		},
		AddWhitelist: func(string) error {
			return fmt.Errorf("%w: whitelist changes are disabled until the privileged Linux firewall integration gate passes", api.ErrEnforcementUnavailable)
		},
		RemoveBlacklist: func(string) error {
			return fmt.Errorf("%w: unban changes are disabled until the privileged Linux firewall integration gate passes", api.ErrEnforcementUnavailable)
		},
		Subscribe: application.events.Subscribe,
		History:   application.history,
	})
	if err != nil {
		return fail(fmt.Errorf("initialize API: %w", err))
	}
	application.api = apiServer

	if err := application.detector.SetHandlers(application.handleSample, application.handleDetectorError); err != nil {
		return fail(fmt.Errorf("connect detector: %w", err))
	}
	application.events.Subscribe(application.logEvent)
	application.events.Subscribe(application.alertOnRuntimeError)
	return application, nil
}

func prepareDirectory(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// Run starts all configured background services and blocks until cancellation
// or a subsystem failure. An Application is intentionally single-use.
func (a *Application) Run(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("runtime context is required")
	}
	a.lifecycleMu.Lock()
	if a.runCalled {
		a.lifecycleMu.Unlock()
		return fmt.Errorf("application runtime may only be started once")
	}
	a.runCalled = true
	runtimeCtx, runtimeCancel := context.WithCancel(ctx)
	a.runCtx = runtimeCtx
	a.lifecycleMu.Unlock()
	defer runtimeCancel()

	var listener net.Listener
	var err error
	if a.cfg.API.Enabled {
		listener, err = net.Listen("tcp", a.cfg.API.BindAddress)
		if err != nil {
			_ = a.logger.Close()
			return fmt.Errorf("bind API address %s: %w", a.cfg.API.BindAddress, err)
		}
	}

	if err := a.detector.Start(); err != nil {
		if listener != nil {
			_ = listener.Close()
		}
		_ = a.logger.Close()
		return fmt.Errorf("start detector: %w", err)
	}

	apiErrors := make(<-chan error)
	if listener != nil {
		apiErrors, err = a.api.StartListener(listener)
		if err != nil {
			_ = listener.Close()
			_ = a.detector.Shutdown(10 * time.Second)
			_ = a.logger.Close()
			return fmt.Errorf("start API server: %w", err)
		}
	}
	a.events.Publish(events.Event{Type: eventRuntimeStarted, Payload: map[string]string{
		"api_enabled":      strconv.FormatBool(a.cfg.API.Enabled),
		"firewall_backend": a.firewall.Describe(runtimeCtx),
	}})
	close(a.ready)

	var runErr error
	if listener == nil {
		<-runtimeCtx.Done()
	} else {
		select {
		case <-runtimeCtx.Done():
		case apiErr := <-apiErrors:
			if apiErr != nil && !errors.Is(apiErr, http.ErrServerClosed) {
				runErr = fmt.Errorf("API server failed: %w", apiErr)
			}
		}
	}
	runtimeCancel()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	apiErr := a.api.Shutdown(shutdownCtx)
	detectorErr := a.detector.Shutdown(10 * time.Second)
	a.events.Publish(events.Event{Type: eventRuntimeStopped})
	logErr := a.logger.Close()
	return errors.Join(runErr, apiErr, detectorErr, logErr)
}

// Ready is closed after all configured listeners and background services have
// started successfully.
func (a *Application) Ready() <-chan struct{} {
	return a.ready
}

// Stats returns a copy of the current runtime snapshot.
func (a *Application) Stats() api.RuntimeStats {
	a.statsMu.RLock()
	defer a.statsMu.RUnlock()
	return a.stats
}

func (a *Application) handleSample(metrics detector.Metrics) {
	signals := a.engine.Evaluate(metrics)
	snapshot := a.monitor.Snapshot(metrics, a.storage.Blacklist().ListLen(), signals)

	a.statsMu.Lock()
	previousStatus := a.stats.AttackStatus
	a.stats = api.RuntimeStats{
		Signals:          len(signals),
		Blocked:          snapshot.BlockedIPs,
		PacketsPerSecond: snapshot.PacketsPerSecond,
		BandwidthMbps:    snapshot.BandwidthMbps,
		AttackStatus:     snapshot.AttackStatus,
		FirewallBackend:  a.firewall.Describe(context.Background()),
		FirewallEnforced: a.firewall.EnforcementEnabled(),
	}
	a.statsMu.Unlock()
	attacks := make([]history.Attack, 0, len(signals))
	for _, signal := range signals {
		attacks = append(attacks, history.Attack{Type: signal.AttackType, Severity: signal.Severity})
	}
	if err := a.history.Record(history.Metric{PacketsPerSecond: metrics.PacketsPerSecond, ConnectionsPerSecond: metrics.ConnectionsPerSecond, BytesPerSecond: metrics.BytesPerSecond, Blocked: snapshot.BlockedIPs, Signals: len(signals)}, attacks); err != nil {
		a.handleDetectorError(fmt.Errorf("persist telemetry history: %w", err))
	}

	a.events.Publish(events.Event{Type: eventSampleCollected, Payload: map[string]string{
		"packets_per_second": strconv.Itoa(metrics.PacketsPerSecond),
		"signals":            strconv.Itoa(len(signals)),
	}})
	if previousStatus != "under_attack" && snapshot.AttackStatus == "under_attack" {
		a.events.Publish(events.Event{Type: eventAttackDetected, Payload: map[string]string{
			"signals": strconv.Itoa(len(signals)),
		}})
	}
	if previousStatus == "under_attack" && snapshot.AttackStatus == "quiet" {
		a.events.Publish(events.Event{Type: eventAttackCleared})
	}
}

func (a *Application) handleDetectorError(err error) {
	a.events.Publish(events.Event{Type: eventRuntimeError, Payload: map[string]string{
		"component": "detector",
		"error":     err.Error(),
	}})
}

func (a *Application) logEvent(event events.Event) {
	fields := make(map[string]string, len(event.Payload)+1)
	fields["event_type"] = event.Type
	for key, value := range event.Payload {
		fields[key] = value
	}
	switch event.Type {
	case eventRuntimeError:
		a.logger.Error("runtime event", fields)
	case eventAttackDetected:
		a.logger.Warn("runtime event", fields)
	default:
		a.logger.Info("runtime event", fields)
	}
}

func (a *Application) alertOnRuntimeError(event events.Event) {
	if event.Type != eventRuntimeError {
		return
	}
	message := fmt.Sprintf("DigitDojo Shield runtime error in %s: %s", event.Payload["component"], event.Payload["error"])
	if err := a.alerts.SendContext(a.runCtx, message); err != nil && !errors.Is(err, context.Canceled) {
		a.logger.Error("alert delivery failed", map[string]string{"error": err.Error()})
	}
}
