package detector

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Daemon periodically gathers kernel and network metrics from the host.
type Daemon struct {
	interval time.Duration

	mu       sync.Mutex
	running  bool
	stopping bool
	cancel   context.CancelFunc
	done     chan struct{}

	sampleFn func() (Metrics, error)
	onSample func(Metrics)
	onError  func(error)
}

// NewDaemon creates a daemon that samples kernel statistics every interval.
func NewDaemon(interval time.Duration) *Daemon {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &Daemon{interval: interval}
}

// SetHandlers connects successful samples and sampling errors to the runtime.
// Handlers must be configured before Start.
func (d *Daemon) SetHandlers(onSample func(Metrics), onError func(error)) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.running || d.stopping {
		return fmt.Errorf("cannot change daemon handlers while running")
	}
	d.onSample = onSample
	d.onError = onError
	return nil
}

// Start begins the sampling loop. Repeated calls while running are safe.
func (d *Daemon) Start() error {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return nil
	}
	if d.stopping {
		d.mu.Unlock()
		return fmt.Errorf("detector daemon is still stopping")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	d.running = true
	d.cancel = cancel
	d.done = done
	onSample := d.onSample
	onError := d.onError
	d.mu.Unlock()

	go d.run(ctx, done, onSample, onError)
	return nil
}

// Stop requests shutdown without waiting for it to finish.
func (d *Daemon) Stop() {
	d.mu.Lock()
	if !d.running || d.stopping {
		d.mu.Unlock()
		return
	}
	d.stopping = true
	cancel := d.cancel
	d.mu.Unlock()
	cancel()
}

func (d *Daemon) run(ctx context.Context, done chan struct{}, onSample func(Metrics), onError func(error)) {
	defer func() {
		if recovered := recover(); recovered != nil && onError != nil {
			onError(fmt.Errorf("detector daemon panic: %v", recovered))
		}
		d.mu.Lock()
		if d.done == done {
			d.running = false
			d.stopping = false
			d.cancel = nil
		}
		d.mu.Unlock()
		close(done)
	}()

	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			metrics, err := d.sampleOnce(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				if onError != nil {
					onError(err)
				}
				continue
			}
			if onSample != nil {
				onSample(metrics)
			}
		}
	}
}

func (d *Daemon) sampleOnce(ctx context.Context) (Metrics, error) {
	if d.sampleFn != nil {
		return d.sampleFn()
	}
	return d.SampleContext(ctx)
}

// Shutdown requests shutdown and waits for completion up to timeout.
func (d *Daemon) Shutdown(timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	d.mu.Lock()
	if !d.running {
		d.mu.Unlock()
		return nil
	}
	d.stopping = true
	done := d.done
	cancel := d.cancel
	d.mu.Unlock()

	cancel()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return fmt.Errorf("detector daemon shutdown timed out")
	}
}

// Running reports whether the sampling goroutine is active.
func (d *Daemon) Running() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.running
}

// Sample collects host metrics without a cancellation deadline.
func (d *Daemon) Sample() (Metrics, error) {
	return d.SampleContext(context.Background())
}

// SampleContext collects host metrics and cancels external commands with ctx.
func (d *Daemon) SampleContext(ctx context.Context) (Metrics, error) {
	metrics := Metrics{}
	ifaceStats, err := readInterfaceStats()
	if err != nil {
		return metrics, err
	}
	if len(ifaceStats) > 0 {
		metrics.PacketsPerSecond = ifaceStats[0].Packets
		metrics.BytesPerSecond = ifaceStats[0].Bytes
	}
	metrics.ConnectionsPerSecond = readConnTrackValue("/proc/sys/net/netfilter/nf_conntrack_acct")
	metrics.UniqueIPs = readUniqueSourceIPs(ctx)
	return metrics, nil
}

type ifaceStat struct {
	Packets int
	Bytes   int
}

func readInterfaceStats() ([]ifaceStat, error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var stats []ifaceStat
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, ":") && !strings.HasPrefix(line, "Inter-|") {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			rxBytes, err := strconv.Atoi(strings.TrimSpace(fields[1]))
			if err != nil {
				continue
			}
			rxPackets, err := strconv.Atoi(strings.TrimSpace(fields[2]))
			if err != nil {
				continue
			}
			stats = append(stats, ifaceStat{Packets: rxPackets, Bytes: rxBytes})
		}
	}
	return stats, scanner.Err()
}

func readConnTrackValue(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return value
}

func readUniqueSourceIPs(ctx context.Context) int {
	out, err := exec.CommandContext(ctx, "ss", "-tan").CombinedOutput()
	if err != nil {
		return 0
	}
	seen := make(map[string]struct{})
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if strings.Contains(fields[0], "ESTAB") && fields[4] != "" {
			seen[fields[4]] = struct{}{}
		}
	}
	return len(seen)
}

// EvaluateSignal uses actual sample metrics to determine whether an attack is present.
func EvaluateSignal(metrics Metrics) []Signal {
	var signals []Signal
	if metrics.PacketsPerSecond > 1000 {
		signals = append(signals, Signal{AttackType: "udp_flood", Severity: "high", Message: fmt.Sprintf("packets/sec=%d", metrics.PacketsPerSecond)})
	}
	if metrics.ConnectionsPerSecond > 100 {
		signals = append(signals, Signal{AttackType: "connection_flood", Severity: "medium", Message: fmt.Sprintf("connections/sec=%d", metrics.ConnectionsPerSecond)})
	}
	return signals
}
