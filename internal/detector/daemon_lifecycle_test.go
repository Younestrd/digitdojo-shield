package detector

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestDaemonStartTwiceIsSafe(t *testing.T) {
	d := NewDaemon(10 * time.Millisecond)
	if err := d.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	if err := d.Start(); err != nil {
		t.Fatalf("second start failed: %v", err)
	}
	d.Stop()
}

func TestDaemonStopTwiceIsSafe(t *testing.T) {
	d := NewDaemon(10 * time.Millisecond)
	if err := d.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	d.Stop()
	d.Stop()
}

func TestDaemonStopBeforeStartIsSafe(t *testing.T) {
	d := NewDaemon(10 * time.Millisecond)
	d.Stop()
}

func TestDaemonConcurrentStartStop(t *testing.T) {
	d := NewDaemon(10 * time.Millisecond)
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = d.Start()
			d.Stop()
		}()
	}
	wg.Wait()
}

func TestDaemonShutdownWithContext(t *testing.T) {
	d := NewDaemon(10 * time.Millisecond)
	if err := d.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = ctx
	if err := d.Shutdown(100 * time.Millisecond); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
}

func TestDaemonShutdownTimeout(t *testing.T) {
	d := NewDaemon(10 * time.Millisecond)
	started := make(chan struct{})
	d.sampleFn = func() (Metrics, error) {
		close(started)
		<-time.After(2 * time.Second)
		return Metrics{}, nil
	}
	if err := d.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	select {
	case <-started:
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("sample did not start")
	}
	if err := d.Shutdown(1 * time.Millisecond); err == nil {
		t.Fatalf("expected timeout error")
	}
}

func TestDaemonDeliversSamplesToHandler(t *testing.T) {
	d := NewDaemon(time.Millisecond)
	d.sampleFn = func() (Metrics, error) {
		return Metrics{PacketsPerSecond: 42}, nil
	}
	received := make(chan Metrics, 1)
	if err := d.SetHandlers(func(metrics Metrics) {
		received <- metrics
	}, nil); err != nil {
		t.Fatalf("set handlers: %v", err)
	}
	if err := d.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	select {
	case metrics := <-received:
		if metrics.PacketsPerSecond != 42 {
			t.Fatalf("unexpected metrics: %+v", metrics)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("sample was not delivered")
	}
	if err := d.Shutdown(100 * time.Millisecond); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if d.Running() {
		t.Fatalf("daemon still reports running after shutdown")
	}
}
