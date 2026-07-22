// Package system provides read-only host inventory collected by the daemon.
package system

import "context"

type Interface struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac"`
	Up        bool     `json:"up"`
	Addresses []string `json:"addresses"`
}
type Disk struct {
	Mount          string `json:"mount"`
	TotalBytes     uint64 `json:"total_bytes"`
	UsedBytes      uint64 `json:"used_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
}
type Inventory struct {
	Hostname             string      `json:"hostname"`
	Distribution         string      `json:"distribution"`
	Kernel               string      `json:"kernel"`
	Architecture         string      `json:"architecture"`
	UptimeSeconds        uint64      `json:"uptime_seconds"`
	CPUModel             string      `json:"cpu_model"`
	CPUCores             int         `json:"cpu_cores"`
	CPUUsagePercent      float64     `json:"cpu_usage_percent"`
	MemoryTotalBytes     uint64      `json:"memory_total_bytes"`
	MemoryAvailableBytes uint64      `json:"memory_available_bytes"`
	LoadAverage          []float64   `json:"load_average"`
	Interfaces           []Interface `json:"interfaces"`
	Disks                []Disk      `json:"disks"`
	NftablesAvailable    bool        `json:"nftables_available"`
	IPTablesAvailable    bool        `json:"iptables_available"`
	DaemonVersion        string      `json:"daemon_version"`
}
type Collector struct{}

func NewCollector() *Collector                                      { return &Collector{} }
func (c *Collector) Collect(ctx context.Context) (Inventory, error) { return collect(ctx, c) }
