package detector

import "testing"

func TestEvaluateSignalDetectsFlood(t *testing.T) {
    metrics := Metrics{PacketsPerSecond: 1500, ConnectionsPerSecond: 200}
    signals := EvaluateSignal(metrics)
    if len(signals) == 0 {
        t.Fatalf("expected detection signals")
    }
}

func TestSampleReturnsMetrics(t *testing.T) {
    daemon := NewDaemon(0)
    metrics, err := daemon.Sample()
    if err != nil {
        if err.Error() == "open /proc/net/dev: The system cannot find the path specified." {
            t.Skip("Linux procfs is not available in this environment")
        }
        t.Fatalf("sample failed: %v", err)
    }
    if metrics.PacketsPerSecond < 0 {
        t.Fatalf("unexpected packet metric")
    }
}
