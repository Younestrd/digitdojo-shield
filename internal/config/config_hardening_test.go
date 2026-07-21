package config

import "testing"

func TestValidateRejectsUnknownSection(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config should validate, got %v", err)
	}
}

func TestValidateRejectsBadBindAddress(t *testing.T) {
	cfg := DefaultConfig()
	cfg.API.Enabled = true
	cfg.API.Token = "secret"
	cfg.API.BindAddress = "bad-address"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected invalid bind address to be rejected")
	}
}

func TestValidateFirewallBackendSelection(t *testing.T) {
	cfg := DefaultConfig()
	for _, selection := range []string{"auto", "nftables", "iptables", "future_backend"} {
		cfg.Firewall.Backend = selection
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected backend %q to validate: %v", selection, err)
		}
	}
	for _, selection := range []string{"", "../nft", "nft tables"} {
		cfg.Firewall.Backend = selection
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected backend %q to be rejected", selection)
		}
	}
}
