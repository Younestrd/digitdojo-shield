package system

import (
	"context"
	"testing"
)

func TestCollectorReturnsHostIdentity(t *testing.T) {
	inventory, err := NewCollector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Hostname == "" {
		t.Fatal("hostname is empty")
	}
	if inventory.Architecture == "" {
		t.Fatal("architecture is empty")
	}
}
