package detector

import "testing"

func TestEvaluateDetectsFloodSignals(t *testing.T) {
    engine := NewEngine(1000)
    metrics := Metrics{PacketsPerSecond: 1200, ConnectionsPerSecond: 800, TopTalkers: []string{"1.1.1.1", "2.2.2.2"}, UniqueIPs: 4}

    signals := engine.Evaluate(metrics)
    if len(signals) == 0 {
        t.Fatalf("expected detection signals, got none")
    }
}

func TestEvaluateUsesDefaultThresholdWhenInvalid(t *testing.T) {
    engine := NewEngine(0)
    metrics := Metrics{PacketsPerSecond: 1000}

    signals := engine.Evaluate(metrics)
    if len(signals) == 0 {
        t.Fatalf("expected default threshold to trigger detection")
    }
}
