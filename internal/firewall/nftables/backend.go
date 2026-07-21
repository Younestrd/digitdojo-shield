package nftables

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"digitdojo-shield/internal/firewall/backend"
)

const snapshotVersion = 1

type Backend struct {
	runner Runner
	now    func() time.Time
	mu     sync.Mutex
}

type snapshotData struct {
	Version int                  `json:"version"`
	Present bool                 `json:"present"`
	State   backend.DesiredState `json:"state"`
}

func NewBackend() (*Backend, error) {
	if err := CheckFirewallEnvironment(); err != nil {
		return nil, err
	}
	path, err := exec.LookPath("nft")
	if err != nil {
		return nil, fmt.Errorf("locate nft executable: %w", err)
	}
	if _, err := CheckNFTVersion(context.Background(), path); err != nil {
		return nil, err
	}
	return NewBackendWithRunner(CommandRunner{Path: path})
}

func NewBackendWithRunner(runner Runner) (*Backend, error) {
	if runner == nil {
		return nil, fmt.Errorf("nftables runner is required")
	}
	return &Backend{runner: runner, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (b *Backend) Name() backend.Name { return backend.NFTables }

func (b *Backend) Snapshot(ctx context.Context) (backend.Snapshot, error) {
	if ctx == nil {
		return backend.Snapshot{}, fmt.Errorf("nftables snapshot requires a non-nil context")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	present, err := b.tableExists(ctx)
	if err != nil {
		return backend.Snapshot{}, err
	}
	data := snapshotData{Version: snapshotVersion, Present: present}
	if present {
		data.State, err = b.inspect(ctx)
		if err != nil {
			return backend.Snapshot{}, err
		}
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return backend.Snapshot{}, fmt.Errorf("encode nftables snapshot: %w", err)
	}
	return backend.Snapshot{Backend: backend.NFTables, Data: encoded}, nil
}

func (b *Backend) Reconcile(ctx context.Context, state backend.DesiredState) error {
	if ctx == nil {
		return fmt.Errorf("nftables reconcile requires a non-nil context")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reconcile(ctx, state)
}

func (b *Backend) reconcile(ctx context.Context, state backend.DesiredState) error {
	program, err := renderRuleset(state, b.now())
	if err != nil {
		return fmt.Errorf("render nftables ruleset: %w", err)
	}
	if _, err := b.runner.Run(ctx, []string{"--check", "--file", "-"}, program); err != nil {
		return fmt.Errorf("validate atomic nftables transaction: %w", err)
	}
	if _, err := b.runner.Run(ctx, []string{"--file", "-"}, program); err != nil {
		return fmt.Errorf("apply atomic nftables transaction: %w", err)
	}
	return nil
}

func (b *Backend) Inspect(ctx context.Context) (backend.DesiredState, error) {
	if ctx == nil {
		return backend.DesiredState{}, fmt.Errorf("nftables inspect requires a non-nil context")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.inspect(ctx)
}

func (b *Backend) inspect(ctx context.Context) (backend.DesiredState, error) {
	present, err := b.tableExists(ctx)
	if err != nil {
		return backend.DesiredState{}, err
	}
	if !present {
		return backend.DesiredState{}, nil
	}
	output, err := b.runner.Run(ctx, []string{"--json", "list", "table", "inet", tableName}, nil)
	if err != nil {
		return backend.DesiredState{}, fmt.Errorf("list Shield nftables table: %w", err)
	}
	state, err := parseRulesetJSON(output, b.now())
	if err != nil {
		return backend.DesiredState{}, fmt.Errorf("parse Shield nftables table: %w", err)
	}
	return state.Normalize(b.now())
}

func (b *Backend) Restore(ctx context.Context, snapshot backend.Snapshot) error {
	if ctx == nil {
		return fmt.Errorf("nftables restore requires a non-nil context")
	}
	if snapshot.Backend != backend.NFTables {
		return fmt.Errorf("nftables cannot restore %s snapshot", snapshot.Backend)
	}
	var data snapshotData
	if err := json.Unmarshal(snapshot.Data, &data); err != nil {
		return fmt.Errorf("decode nftables snapshot: %w", err)
	}
	if data.Version != snapshotVersion {
		return fmt.Errorf("unsupported nftables snapshot version %d", data.Version)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !data.Present {
		return b.cleanup(ctx)
	}
	return b.reconcile(ctx, data.State)
}

func (b *Backend) Cleanup(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("nftables cleanup requires a non-nil context")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cleanup(ctx)
}

func (b *Backend) cleanup(ctx context.Context) error {
	program := []byte("destroy table inet " + tableName + "\n")
	if _, err := b.runner.Run(ctx, []string{"--check", "--file", "-"}, program); err != nil {
		return fmt.Errorf("validate Shield nftables cleanup: %w", err)
	}
	if _, err := b.runner.Run(ctx, []string{"--file", "-"}, program); err != nil {
		return fmt.Errorf("cleanup Shield nftables table: %w", err)
	}
	return nil
}

func (b *Backend) tableExists(ctx context.Context) (bool, error) {
	output, err := b.runner.Run(ctx, []string{"list", "tables"}, nil)
	if err != nil {
		return false, fmt.Errorf("list nftables tables: %w", err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.TrimSpace(line) == "table inet "+tableName {
			return true, nil
		}
	}
	return false, nil
}

func parseRulesetJSON(input []byte, now time.Time) (backend.DesiredState, error) {
	var document struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(input, &document); err != nil {
		return backend.DesiredState{}, err
	}
	sets := make(map[string][]json.RawMessage)
	for _, object := range document.NFTables {
		raw, exists := object["set"]
		if !exists {
			continue
		}
		var set struct {
			Family string            `json:"family"`
			Table  string            `json:"table"`
			Name   string            `json:"name"`
			Elem   []json.RawMessage `json:"elem"`
		}
		if err := json.Unmarshal(raw, &set); err != nil {
			return backend.DesiredState{}, err
		}
		if set.Family == "inet" && set.Table == tableName {
			sets[set.Name] = set.Elem
		}
	}
	var state backend.DesiredState
	for _, name := range []string{"whitelist_v4", "whitelist_v6"} {
		addresses, err := parseAddressElements(sets[name])
		if err != nil {
			return backend.DesiredState{}, fmt.Errorf("set %s: %w", name, err)
		}
		state.Whitelist = append(state.Whitelist, addresses...)
	}
	for _, name := range []string{"permanent_bans_v4", "permanent_bans_v6"} {
		addresses, err := parseAddressElements(sets[name])
		if err != nil {
			return backend.DesiredState{}, fmt.Errorf("set %s: %w", name, err)
		}
		state.PermanentBans = append(state.PermanentBans, addresses...)
	}
	for _, name := range []string{"temporary_bans_v4", "temporary_bans_v6"} {
		bans, err := parseTemporaryElements(sets[name], now)
		if err != nil {
			return backend.DesiredState{}, fmt.Errorf("set %s: %w", name, err)
		}
		state.TemporaryBans = append(state.TemporaryBans, bans...)
	}
	sort.Slice(state.TemporaryBans, func(i, j int) bool {
		return state.TemporaryBans[i].Address.Compare(state.TemporaryBans[j].Address) < 0
	})
	return state, nil
}

func parseAddressElements(elements []json.RawMessage) ([]netip.Addr, error) {
	addresses := make([]netip.Addr, 0, len(elements))
	for _, element := range elements {
		address, _, err := parseElement(element)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

func parseTemporaryElements(elements []json.RawMessage, now time.Time) ([]backend.TemporaryBan, error) {
	bans := make([]backend.TemporaryBan, 0, len(elements))
	for _, element := range elements {
		address, expires, err := parseElement(element)
		if err != nil {
			return nil, err
		}
		if expires <= 0 {
			return nil, fmt.Errorf("temporary element %s has no remaining expiry", address)
		}
		// libnftables JSON represents set-element timeout and expiry values in seconds.
		bans = append(bans, backend.TemporaryBan{Address: address, ExpiresAt: now.Add(time.Duration(expires) * time.Second)})
	}
	return bans, nil
}

func parseElement(raw json.RawMessage) (netip.Addr, int64, error) {
	var addressText string
	if err := json.Unmarshal(raw, &addressText); err == nil {
		address, parseErr := netip.ParseAddr(addressText)
		return address, 0, parseErr
	}
	var wrapper struct {
		Element *struct {
			Value   json.RawMessage `json:"val"`
			Expires int64           `json:"expires"`
		} `json:"elem"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil || wrapper.Element == nil {
		return netip.Addr{}, 0, fmt.Errorf("unsupported nftables set element %s", raw)
	}
	if err := json.Unmarshal(wrapper.Element.Value, &addressText); err != nil {
		return netip.Addr{}, 0, fmt.Errorf("decode nftables address: %w", err)
	}
	address, err := netip.ParseAddr(addressText)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	return address, wrapper.Element.Expires, nil
}
