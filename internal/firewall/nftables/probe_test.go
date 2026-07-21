package nftables

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

func TestProbeDistinguishesCommandDetectionFromImplementation(t *testing.T) {
	capability := NewProbe(locator{"nft": "/usr/sbin/nft"}).Detect(context.Background())
	if !capability.Detected || capability.Implemented {
		t.Fatalf("unexpected capability: %+v", capability)
	}
	if capability.Commands["nft"] != "/usr/sbin/nft" {
		t.Fatalf("nft path was not retained")
	}
}

func TestProbeReportsMissingAndCancellation(t *testing.T) {
	missing := NewProbe(locator{}).Detect(context.Background())
	if missing.Detected || len(missing.Missing) != 1 {
		t.Fatalf("unexpected missing capability: %+v", missing)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelled := NewProbe(locator{"nft": "/usr/sbin/nft"}).Detect(ctx)
	if cancelled.Detected || cancelled.Reason == "" {
		t.Fatalf("cancelled probe should not report detection: %+v", cancelled)
	}
}

func TestRuntimeProbeRequiresSupportedVersionAndCapabilities(t *testing.T) {
	t.Run("unsupported version", func(t *testing.T) {
		probe := NewRuntimeProbe(locator{"nft": "/usr/sbin/nft"})
		probe.versionCheck = func(context.Context, string) (Version, error) {
			return Version{}, errors.New("nftables 1.0.8 is unsupported")
		}
		probe.environmentCheck = func() error { return nil }
		capability := probe.Detect(context.Background())
		if capability.Detected || len(capability.Missing) != 1 || capability.Missing[0] != "nft>="+MinimumSupportedVersion {
			t.Fatalf("unsupported version was not rejected: %+v", capability)
		}
	})
	t.Run("missing capability", func(t *testing.T) {
		probe := NewRuntimeProbe(locator{"nft": "/usr/sbin/nft"})
		probe.versionCheck = func(context.Context, string) (Version, error) { return Version{Major: 1, Minor: 0, Patch: 9}, nil }
		probe.environmentCheck = func() error { return errors.New("CAP_NET_ADMIN is missing") }
		capability := probe.Detect(context.Background())
		if capability.Detected || !strings.Contains(capability.Reason, "CAP_NET_ADMIN") || capability.Commands["nft_version"] != "1.0.9" {
			t.Fatalf("missing capability was not reported clearly: %+v", capability)
		}
	})
}
