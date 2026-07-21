package iptables

import (
	"context"
	"fmt"
	"testing"
)

type locator map[string]string

func (l locator) LookPath(command string) (string, error) {
	path, exists := l[command]
	if !exists {
		return "", fmt.Errorf("missing")
	}
	return path, nil
}

func TestProbeRequiresIPv4AndIPv6Tooling(t *testing.T) {
	paths := locator{}
	for _, command := range requiredCommands {
		paths[command] = "/usr/sbin/" + command
	}
	capability := NewProbe(paths).Detect(context.Background())
	if !capability.Detected || capability.Implemented || len(capability.Missing) != 0 {
		t.Fatalf("unexpected capability: %+v", capability)
	}

	delete(paths, "ip6tables-restore")
	missing := NewProbe(paths).Detect(context.Background())
	if missing.Detected || len(missing.Missing) != 1 || missing.Missing[0] != "ip6tables-restore" {
		t.Fatalf("missing IPv6 tooling was not reported: %+v", missing)
	}
}
