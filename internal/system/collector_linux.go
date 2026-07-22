//go:build linux

package system

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func collect(ctx context.Context, c *Collector) (Inventory, error) {
	hostname, _ := os.Hostname()
	inventory := Inventory{Hostname: hostname, Architecture: runtime.GOARCH, DaemonVersion: "1.0.0", Distribution: readDistribution(), Kernel: readKernel(), CPUCores: runtime.NumCPU(), Interfaces: readInterfaces(), LoadAverage: readLoadAverage(), NftablesAvailable: commandAvailable(ctx, "nft"), IPTablesAvailable: commandAvailable(ctx, "iptables")}
	inventory.UptimeSeconds = readUptime()
	inventory.CPUModel = readCPUModel()
	inventory.CPUUsagePercent = readCPUUsage(ctx)
	inventory.MemoryTotalBytes, inventory.MemoryAvailableBytes = readMemory()
	inventory.Disks = readDisks()
	return inventory, nil
}
func readDistribution() string {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return "unknown"
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "PRETTY_NAME=") {
			return strings.Trim(scanner.Text()[12:], "\"")
		}
	}
	return "unknown"
}
func readKernel() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}
func readUptime() uint64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	value := strings.Fields(string(data))
	if len(value) == 0 {
		return 0
	}
	n, _ := strconv.ParseFloat(value[0], 64)
	return uint64(n)
}
func readCPUModel() string {
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return "unknown"
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return "unknown"
}
func readCPUUsage(ctx context.Context) float64 {
	firstTotal, firstIdle, ok := cpuTicks()
	if !ok {
		return 0
	}
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return 0
	case <-timer.C:
	}
	secondTotal, secondIdle, ok := cpuTicks()
	if !ok || secondTotal <= firstTotal {
		return 0
	}
	return float64((secondTotal-firstTotal)-(secondIdle-firstIdle)) * 100 / float64(secondTotal-firstTotal)
}
func cpuTicks() (uint64, uint64, bool) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	fields := strings.Fields(strings.SplitN(string(data), "\n", 2)[0])
	if len(fields) < 5 {
		return 0, 0, false
	}
	var total uint64
	for _, field := range fields[1:] {
		value, error := strconv.ParseUint(field, 10, 64)
		if error != nil {
			return 0, 0, false
		}
		total += value
	}
	idle, error := strconv.ParseUint(fields[4], 10, 64)
	return total, idle, error == nil
}
func readMemory() (uint64, uint64) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer file.Close()
	var total, available uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		p := strings.Fields(scanner.Text())
		if len(p) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(p[1], 10, 64)
		switch p[0] {
		case "MemTotal:":
			total = v * 1024
		case "MemAvailable:":
			available = v * 1024
		}
	}
	return total, available
}
func readLoadAverage() []float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil
	}
	fields := strings.Fields(string(data))
	result := make([]float64, 0, 3)
	for _, f := range fields[:min(3, len(fields))] {
		v, err := strconv.ParseFloat(f, 64)
		if err == nil {
			result = append(result, v)
		}
	}
	return result
}
func readInterfaces() []Interface {
	interfaces, _ := net.Interfaces()
	out := make([]Interface, 0, len(interfaces))
	for _, iface := range interfaces {
		addresses, _ := iface.Addrs()
		ips := make([]string, 0, len(addresses))
		for _, address := range addresses {
			ips = append(ips, address.String())
		}
		out = append(out, Interface{Name: iface.Name, MAC: iface.HardwareAddr.String(), Up: iface.Flags&net.FlagUp != 0, Addresses: ips})
	}
	return out
}
func readDisks() []Disk {
	var fs syscall.Statfs_t
	if syscall.Statfs("/", &fs) != nil {
		return nil
	}
	size := fs.Bsize
	return []Disk{{Mount: "/", TotalBytes: fs.Blocks * uint64(size), AvailableBytes: fs.Bavail * uint64(size), UsedBytes: (fs.Blocks - fs.Bfree) * uint64(size)}}
}
func commandAvailable(ctx context.Context, name string) bool {
	path, err := exec.LookPath(name)
	if err != nil {
		return false
	}
	command := exec.CommandContext(ctx, path, "--version")
	return command.Run() == nil
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
