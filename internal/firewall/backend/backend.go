// Package backend defines the firewall contracts shared by all implementations.
package backend

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Name string

const (
	Auto     Name = "auto"
	NFTables Name = "nftables"
	IPTables Name = "iptables"
)

var validName = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

func ParseName(value string) (Name, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	name := Name(value)
	if !validName.MatchString(value) {
		return "", fmt.Errorf("invalid firewall backend name %q", value)
	}
	return name, nil
}

// Capability separates host tooling detection from implementation readiness.
type Capability struct {
	Name        Name
	Detected    bool
	Implemented bool
	Commands    map[string]string
	Missing     []string
	Reason      string
}

// Probe detects userspace prerequisites without modifying firewall state.
type Probe interface {
	Name() Name
	Detect(context.Context) Capability
}

// CommandLocator makes command discovery deterministic and unit-testable.
type CommandLocator interface {
	LookPath(string) (string, error)
}

type ExecLocator struct{}

func (ExecLocator) LookPath(command string) (string, error) {
	return exec.LookPath(command)
}

type TemporaryBan struct {
	Address   netip.Addr
	ExpiresAt time.Time
}

// DesiredState is the complete declarative state of Shield-managed objects.
// Backends must evaluate whitelist entries before either ban set.
type DesiredState struct {
	Whitelist     []netip.Addr
	PermanentBans []netip.Addr
	TemporaryBans []TemporaryBan
}

// Normalize validates addresses, removes expired bans and duplicates, and
// returns deterministic ordering suitable for reconciliation.
func (s DesiredState) Normalize(now time.Time) (DesiredState, error) {
	whitelist, err := normalizeAddresses(s.Whitelist)
	if err != nil {
		return DesiredState{}, fmt.Errorf("normalize whitelist: %w", err)
	}
	permanent, err := normalizeAddresses(s.PermanentBans)
	if err != nil {
		return DesiredState{}, fmt.Errorf("normalize permanent bans: %w", err)
	}

	temporaryByAddress := make(map[netip.Addr]time.Time, len(s.TemporaryBans))
	for _, ban := range s.TemporaryBans {
		address, err := normalizeAddress(ban.Address)
		if err != nil {
			return DesiredState{}, fmt.Errorf("normalize temporary ban: %w", err)
		}
		if ban.ExpiresAt.IsZero() {
			return DesiredState{}, fmt.Errorf("temporary ban for %s has no expiry", address)
		}
		if !ban.ExpiresAt.After(now) {
			continue
		}
		if current, exists := temporaryByAddress[address]; !exists || ban.ExpiresAt.After(current) {
			temporaryByAddress[address] = ban.ExpiresAt.UTC()
		}
	}
	temporary := make([]TemporaryBan, 0, len(temporaryByAddress))
	for address, expiresAt := range temporaryByAddress {
		temporary = append(temporary, TemporaryBan{Address: address, ExpiresAt: expiresAt})
	}
	sort.Slice(temporary, func(i, j int) bool {
		return temporary[i].Address.Compare(temporary[j].Address) < 0
	})

	return DesiredState{Whitelist: whitelist, PermanentBans: permanent, TemporaryBans: temporary}, nil
}

func normalizeAddresses(addresses []netip.Addr) ([]netip.Addr, error) {
	unique := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		normalized, err := normalizeAddress(address)
		if err != nil {
			return nil, err
		}
		unique[normalized] = struct{}{}
	}
	result := make([]netip.Addr, 0, len(unique))
	for address := range unique {
		result = append(result, address)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Compare(result[j]) < 0
	})
	return result, nil
}

func normalizeAddress(address netip.Addr) (netip.Addr, error) {
	if !address.IsValid() {
		return netip.Addr{}, fmt.Errorf("invalid IP address")
	}
	address = address.Unmap()
	if address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
		return netip.Addr{}, fmt.Errorf("unsafe IP address %s", address)
	}
	return address, nil
}

// Snapshot is an opaque, backend-specific copy of Shield-managed objects only.
type Snapshot struct {
	Backend Name
	Data    []byte
}

// Backend is the privileged firewall boundary. Implementations must restrict
// every operation to the dedicated DigitDojo Shield table or equivalent owned
// objects. Reconcile must be atomic and idempotent. Restore must accept only
// snapshots created by the same backend.
type Backend interface {
	Name() Name
	Snapshot(context.Context) (Snapshot, error)
	Reconcile(context.Context, DesiredState) error
	Inspect(context.Context) (DesiredState, error)
	Restore(context.Context, Snapshot) error
	Cleanup(context.Context) error
}

type Factory func() (Backend, error)
