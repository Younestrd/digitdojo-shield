package monitor

import (
    "fmt"
    "runtime"

    "digitdojo-shield/internal/detector"
)

type Stats struct {
    PacketsPerSecond int
    BandwidthMbps int
    BlockedIPs int
    AttackStatus string
    CPUPercent float64
    RAMMB float64
    NetworkUsageMB float64
    TopAttackers []string
}

type Monitor struct {
    blockedIPs int
    attackStatus string
}

func New() *Monitor {
    return &Monitor{attackStatus: "quiet"}
}

func (m *Monitor) Snapshot(metrics detector.Metrics, blockedIPs int, signals []detector.Signal) Stats {
    var attackStatus string
    if len(signals) > 0 {
        attackStatus = "under_attack"
    } else {
        attackStatus = "quiet"
    }
    m.blockedIPs = blockedIPs
    m.attackStatus = attackStatus

    var mem runtime.MemStats
    runtime.ReadMemStats(&mem)
    ramMB := float64(mem.Alloc) / (1024 * 1024)

    return Stats{
        PacketsPerSecond: metrics.PacketsPerSecond,
        BandwidthMbps: metrics.BytesPerSecond / (1024 * 1024),
        BlockedIPs: blockedIPs,
        AttackStatus: attackStatus,
        CPUPercent: 0.0,
        RAMMB: ramMB,
        NetworkUsageMB: float64(metrics.BytesPerSecond) / (1024 * 1024),
        TopAttackers: metrics.TopTalkers,
    }
}

func (m *Monitor) String() string {
    return fmt.Sprintf("status=%s blocked=%d", m.attackStatus, m.blockedIPs)
}
