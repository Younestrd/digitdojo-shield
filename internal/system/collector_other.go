//go:build !linux

package system

import (
	"context"
	"os"
	"runtime"
)

func collect(_ context.Context, _ *Collector) (Inventory, error) {
	hostname, _ := os.Hostname()
	return Inventory{Hostname: hostname, Architecture: runtime.GOARCH, DaemonVersion: "1.0.0", Distribution: "unsupported", Kernel: "unsupported", CPUCores: runtime.NumCPU()}, nil
}
