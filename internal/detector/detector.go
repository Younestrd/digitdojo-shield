package detector

type Metrics struct {
    PacketsPerSecond int
    ConnectionsPerSecond int
    BytesPerSecond int
    UniqueIPs int
    TopTalkers []string
}

type Signal struct {
    AttackType string
    Severity string
    Message string
}

type Engine struct {
    threshold int
}

func NewEngine(threshold int) *Engine {
    if threshold <= 0 {
        threshold = 1000
    }
    return &Engine{threshold: threshold}
}

func (e *Engine) Evaluate(metrics Metrics) []Signal {
    var signals []Signal
    if metrics.PacketsPerSecond >= e.threshold {
        signals = append(signals, Signal{AttackType: "udp_flood", Severity: "high", Message: "packet rate exceeded threshold"})
    }
    if metrics.ConnectionsPerSecond >= e.threshold/2 {
        signals = append(signals, Signal{AttackType: "connection_flood", Severity: "medium", Message: "connection rate exceeded threshold"})
    }
    if len(metrics.TopTalkers) > 0 && metrics.UniqueIPs > 0 && len(metrics.TopTalkers) >= metrics.UniqueIPs/2 {
        signals = append(signals, Signal{AttackType: "port_scan", Severity: "medium", Message: "suspicious concentration of unique talking hosts"})
    }
    return signals
}
