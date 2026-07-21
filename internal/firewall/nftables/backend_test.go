package nftables

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"digitdojo-shield/internal/firewall/backend"
)

type runnerCall struct {
	args  []string
	input string
}

type runnerResult struct {
	output string
	err    error
}

type scriptedRunner struct {
	mu      sync.Mutex
	results []runnerResult
	calls   []runnerCall
}

func (r *scriptedRunner) Run(_ context.Context, args []string, input []byte) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, runnerCall{args: append([]string(nil), args...), input: string(input)})
	if len(r.results) == 0 {
		return nil, nil
	}
	result := r.results[0]
	r.results = r.results[1:]
	return []byte(result.output), result.err
}

func TestRenderRulesetOwnsOneTableAndOrdersWhitelistFirst(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 500_000_000, time.UTC)
	state := backend.DesiredState{
		Whitelist:     []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")},
		PermanentBans: []netip.Addr{netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("2001:db8::20")},
		TemporaryBans: []backend.TemporaryBan{
			{Address: netip.MustParseAddr("192.0.2.30"), ExpiresAt: now.Add(1500 * time.Millisecond)},
			{Address: netip.MustParseAddr("2001:db8::30"), ExpiresAt: now.Add(2 * time.Second)},
		},
	}
	program, err := renderRuleset(state, now)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	text := string(program)
	if strings.Count(text, "add table inet "+tableName) != 1 || strings.Contains(text, "flush ruleset") {
		t.Fatalf("ruleset does not preserve ownership boundary:\n%s", text)
	}
	if !strings.Contains(text, "192.0.2.30 timeout 2s") || !strings.Contains(text, "2001:db8::30 timeout 2s") {
		t.Fatalf("temporary timeouts were not rounded safely:\n%s", text)
	}
	whitelist := strings.Index(text, "ip saddr @whitelist_v4 accept")
	permanent := strings.Index(text, "ip saddr @permanent_bans_v4 drop")
	temporary := strings.Index(text, "ip saddr @temporary_bans_v4 drop")
	if whitelist < 0 || permanent < 0 || temporary < 0 || !(whitelist < permanent && permanent < temporary) {
		t.Fatalf("IPv4 whitelist precedence is missing:\n%s", text)
	}
	if strings.Count(text, "add chain inet "+tableName) != 2 {
		t.Fatalf("expected dedicated base and policy chains:\n%s", text)
	}
}

func TestBackendReconcileChecksThenAppliesSameAtomicBatch(t *testing.T) {
	runner := &scriptedRunner{}
	implementation, err := NewBackendWithRunner(runner)
	if err != nil {
		t.Fatalf("create backend: %v", err)
	}
	if err := implementation.Reconcile(context.Background(), backend.DesiredState{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("expected check and apply, got %d calls", len(runner.calls))
	}
	if strings.Join(runner.calls[0].args, " ") != "--check --file -" || strings.Join(runner.calls[1].args, " ") != "--file -" {
		t.Fatalf("unexpected nft arguments: %+v", runner.calls)
	}
	if runner.calls[0].input == "" || runner.calls[0].input != runner.calls[1].input {
		t.Fatalf("validation and apply did not receive the same batch")
	}
}

func TestBackendNeverAppliesBatchThatFailsValidation(t *testing.T) {
	runner := &scriptedRunner{results: []runnerResult{{err: errors.New("invalid batch")}}}
	implementation, _ := NewBackendWithRunner(runner)
	if err := implementation.Reconcile(context.Background(), backend.DesiredState{}); err == nil || !strings.Contains(err.Error(), "validate") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("invalid batch reached apply: %+v", runner.calls)
	}
}

func TestBackendInspectParsesIPv4IPv6AndRemainingTimeouts(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	runner := &scriptedRunner{results: []runnerResult{
		{output: "table inet digitdojo_shield\n"},
		{output: `{"nftables":[
			{"metainfo":{"json_schema_version":1}},
			{"set":{"family":"inet","table":"digitdojo_shield","name":"whitelist_v4","elem":["192.0.2.1"]}},
			{"set":{"family":"inet","table":"digitdojo_shield","name":"whitelist_v6","elem":["2001:db8::1"]}},
			{"set":{"family":"inet","table":"digitdojo_shield","name":"permanent_bans_v4","elem":["192.0.2.2"]}},
			{"set":{"family":"inet","table":"digitdojo_shield","name":"temporary_bans_v6","elem":[{"elem":{"val":"2001:db8::2","timeout":5,"expires":3}}]}}
		]}`},
	}}
	implementation, _ := NewBackendWithRunner(runner)
	implementation.now = func() time.Time { return now }
	state, err := implementation.Inspect(context.Background())
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if len(state.Whitelist) != 2 || len(state.PermanentBans) != 1 || len(state.TemporaryBans) != 1 {
		t.Fatalf("unexpected state: %+v", state)
	}
	if !state.TemporaryBans[0].ExpiresAt.Equal(now.Add(3 * time.Second)) {
		t.Fatalf("unexpected expiry: %s", state.TemporaryBans[0].ExpiresAt)
	}
}

func TestBackendSnapshotAndRestoreAreConstrainedToTypedState(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	runner := &scriptedRunner{results: []runnerResult{
		{output: "table inet digitdojo_shield\n"},
		{output: "table inet digitdojo_shield\n"},
		{output: `{"nftables":[{"set":{"family":"inet","table":"digitdojo_shield","name":"permanent_bans_v4","elem":["192.0.2.44"]}}]}`},
	}}
	implementation, _ := NewBackendWithRunner(runner)
	implementation.now = func() time.Time { return now }
	snapshot, err := implementation.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snapshot.Backend != backend.NFTables || !strings.Contains(string(snapshot.Data), "192.0.2.44") {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	if err := implementation.Restore(context.Background(), snapshot); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if len(runner.calls) != 5 || !strings.Contains(runner.calls[4].input, "192.0.2.44") {
		t.Fatalf("restore did not reconcile typed Shield state: %+v", runner.calls)
	}
	malicious := backend.Snapshot{Backend: backend.NFTables, Data: []byte("flush ruleset")}
	before := len(runner.calls)
	if err := implementation.Restore(context.Background(), malicious); err == nil {
		t.Fatalf("untyped snapshot was accepted")
	}
	if len(runner.calls) != before {
		t.Fatalf("malformed snapshot reached nft")
	}
}

func TestBackendRestoresAnAbsentTableByOwnedCleanup(t *testing.T) {
	runner := &scriptedRunner{results: []runnerResult{{output: "table inet unrelated\n"}}}
	implementation, _ := NewBackendWithRunner(runner)
	snapshot, err := implementation.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("snapshot absent table: %v", err)
	}
	if !strings.Contains(string(snapshot.Data), `"present":false`) {
		t.Fatalf("snapshot did not retain table absence: %s", snapshot.Data)
	}
	if err := implementation.Restore(context.Background(), snapshot); err != nil {
		t.Fatalf("restore absent table: %v", err)
	}
	if len(runner.calls) != 3 || runner.calls[1].input != "destroy table inet digitdojo_shield\n" {
		t.Fatalf("absent-state restore did not use owned cleanup: %+v", runner.calls)
	}
}

func TestBackendCleanupUsesOnlyIdempotentOwnedTableDestroy(t *testing.T) {
	runner := &scriptedRunner{}
	implementation, _ := NewBackendWithRunner(runner)
	if err := implementation.Cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if len(runner.calls) != 2 || runner.calls[0].input != "destroy table inet digitdojo_shield\n" || runner.calls[1].input != runner.calls[0].input {
		t.Fatalf("unexpected cleanup transaction: %+v", runner.calls)
	}
}

func TestBackendRejectsNilContextsAndWrongSnapshots(t *testing.T) {
	if _, err := NewBackendWithRunner(nil); err == nil {
		t.Fatalf("expected nil runner rejection")
	}
	implementation, _ := NewBackendWithRunner(&scriptedRunner{})
	if err := implementation.Reconcile(nil, backend.DesiredState{}); err == nil {
		t.Fatalf("expected nil reconcile context rejection")
	}
	if _, err := implementation.Inspect(nil); err == nil {
		t.Fatalf("expected nil inspect context rejection")
	}
	if _, err := implementation.Snapshot(nil); err == nil {
		t.Fatalf("expected nil snapshot context rejection")
	}
	if err := implementation.Cleanup(nil); err == nil {
		t.Fatalf("expected nil cleanup context rejection")
	}
	if err := implementation.Restore(context.Background(), backend.Snapshot{Backend: backend.IPTables}); err == nil {
		t.Fatalf("expected cross-backend snapshot rejection")
	}
}
