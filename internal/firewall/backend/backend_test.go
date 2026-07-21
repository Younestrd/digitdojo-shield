package backend

import (
	"net/netip"
	"testing"
	"time"
)

func TestParseNameNormalizesSelection(t *testing.T) {
	name, err := ParseName(" NFTables ")
	if err != nil {
		t.Fatalf("parse name: %v", err)
	}
	if name != NFTables {
		t.Fatalf("unexpected normalized name: %s", name)
	}
	for _, value := range []string{"", "../nft", "nft tables", "_hidden"} {
		if _, err := ParseName(value); err == nil {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}

func TestDesiredStateNormalizeSupportsBothFamiliesAndPrecedenceOverlap(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	v4 := netip.MustParseAddr("192.0.2.10")
	v4Mapped := netip.MustParseAddr("::ffff:192.0.2.10")
	v6 := netip.MustParseAddr("2001:db8::10")
	state, err := (DesiredState{
		Whitelist:     []netip.Addr{v6, v4, v4Mapped},
		PermanentBans: []netip.Addr{v4, v6},
		TemporaryBans: []TemporaryBan{
			{Address: v4, ExpiresAt: now.Add(time.Minute)},
			{Address: v4Mapped, ExpiresAt: now.Add(2 * time.Minute)},
			{Address: v6, ExpiresAt: now.Add(-time.Second)},
		},
	}).Normalize(now)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(state.Whitelist) != 2 || state.Whitelist[0] != v4 || state.Whitelist[1] != v6 {
		t.Fatalf("unexpected whitelist: %v", state.Whitelist)
	}
	if len(state.PermanentBans) != 2 {
		t.Fatalf("overlapping bans should remain declarative for whitelist precedence: %v", state.PermanentBans)
	}
	if len(state.TemporaryBans) != 1 || state.TemporaryBans[0].Address != v4 || !state.TemporaryBans[0].ExpiresAt.Equal(now.Add(2*time.Minute)) {
		t.Fatalf("unexpected temporary bans: %+v", state.TemporaryBans)
	}
}

func TestDesiredStateNormalizeRejectsUnsafeAddressesAndMissingExpiry(t *testing.T) {
	now := time.Now()
	unsafe := []netip.Addr{
		netip.Addr{},
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("::1"),
		netip.MustParseAddr("224.0.0.1"),
		netip.MustParseAddr("fe80::1"),
	}
	for _, address := range unsafe {
		if _, err := (DesiredState{PermanentBans: []netip.Addr{address}}).Normalize(now); err == nil {
			t.Fatalf("expected %s to be rejected", address)
		}
	}
	if _, err := (DesiredState{TemporaryBans: []TemporaryBan{{Address: netip.MustParseAddr("192.0.2.1")}}}).Normalize(now); err == nil {
		t.Fatalf("expected missing temporary-ban expiry to be rejected")
	}
}
