package monitor

import (
    "testing"

    "digitdojo-shield/internal/detector"
)

func TestSnapshotReportsAttackStatus(t *testing.T) {
    m := New()
    metrics := detector.Metrics{PacketsPerSecond: 1500, BytesPerSecond: 1048576, TopTalkers: []string{"1.1.1.1"}}
    stats := m.Snapshot(metrics, 2, []detector.Signal{{AttackType: "udp_flood"}})
    if stats.AttackStatus != "under_attack" {
        t.Fatalf("expected under_attack status, got %s", stats.AttackStatus)
    }
}
