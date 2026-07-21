package config

import "testing"

func TestDefaultConfigIsValid(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected default config to be valid, got %v", err)
	}
}

func TestValidateIPRejectsLoopback(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.ValidateIP("127.0.0.1"); err == nil {
		t.Fatalf("expected loopback IP to be rejected")
	}
}

func TestValidateIPAcceptsPublicIP(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.ValidateIP("8.8.8.8"); err != nil {
		t.Fatalf("expected public IP to be accepted, got %v", err)
	}
}
