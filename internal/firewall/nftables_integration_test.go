//go:build linux && integration

package firewall

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"digitdojo-shield/internal/firewall/backend"
	shieldnft "digitdojo-shield/internal/firewall/nftables"
)

const (
	protectedIPv4 = "192.0.2.1:22"
	clientIPv4    = "192.0.2.2"
	protectedIPv6 = "[2001:db8:1::1]:22"
	clientIPv6    = "2001:db8:1::2"
	blockedIPv4   = "192.0.2.1:8080"
	blockedIPv6   = "[2001:db8:1::1]:8080"
)

type namespaceRunner struct {
	namespace string
}

type listenerSpec struct {
	network string
	address string
}

var namespaceListenerSpecs = []listenerSpec{
	{network: "tcp4", address: "0.0.0.0:22"},
	{network: "tcp6", address: "[::]:22"},
	{network: "tcp4", address: "0.0.0.0:8080"},
	{network: "tcp6", address: "[::]:8080"},
}

func (r namespaceRunner) Run(ctx context.Context, args []string, input []byte) ([]byte, error) {
	commandArgs := append([]string{"netns", "exec", r.namespace, "nft"}, args...)
	command := exec.CommandContext(ctx, "ip", commandArgs...)
	command.Stdin = bytes.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ip %v: %w: %s", commandArgs, err, bytes.TrimSpace(output))
	}
	return output, nil
}

type integrationProbe struct{}

func (integrationProbe) Name() backend.Name { return backend.NFTables }
func (integrationProbe) Detect(context.Context) backend.Capability {
	return backend.Capability{Name: backend.NFTables, Detected: true}
}

type failAfterApplyRunner struct {
	delegate shieldnft.Runner
	mu       sync.Mutex
	failed   bool
}

func (r *failAfterApplyRunner) Run(ctx context.Context, args []string, input []byte) ([]byte, error) {
	output, err := r.delegate.Run(ctx, args, input)
	if err != nil {
		return output, err
	}
	if len(args) == 2 && args[0] == "--file" && args[1] == "-" {
		r.mu.Lock()
		defer r.mu.Unlock()
		if !r.failed && bytes.Contains(input, []byte("add table inet digitdojo_shield")) {
			r.failed = true
			return output, fmt.Errorf("injected post-apply verification failure")
		}
	}
	return output, nil
}

func TestNFTablesLinuxIntegration(t *testing.T) {
	requireLinuxFirewallEnvironment(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	hostBefore := commandOutput(t, ctx, nil, "nft", "--json", "list", "ruleset")

	protectedNamespace := namespaceName("shieldp")
	clientNamespace := namespaceName("shieldc")
	protectedLink := linkName("sp")
	clientLink := linkName("sc")
	defer func() {
		if t.Failed() {
			if diagnostics, err := exec.Command("ip", "netns", "exec", protectedNamespace, "nft", "list", "ruleset").CombinedOutput(); err == nil {
				t.Logf("protected namespace ruleset:\n%s", diagnostics)
			}
		}
		commandBestEffort("ip", "netns", "delete", clientNamespace)
		commandBestEffort("ip", "netns", "delete", protectedNamespace)
		hostAfter, err := exec.Command("nft", "--json", "list", "ruleset").Output()
		if err != nil {
			t.Errorf("read host ruleset after test: %v", err)
		} else if !bytes.Equal(normalizeNFTJSON(t, hostBefore), normalizeNFTJSON(t, hostAfter)) {
			t.Errorf("host namespace nftables rules changed")
		}
	}()
	setupNamespaces(t, ctx, protectedNamespace, clientNamespace, protectedLink, clientLink)

	runner := namespaceRunner{namespace: protectedNamespace}
	unrelatedProgram := []byte(`add table inet preexisting_test
add set inet preexisting_test marker { type ipv4_addr; elements = { 198.51.100.10 }; }
add chain inet preexisting_test input { type filter hook input priority 0; policy drop; }
add rule inet preexisting_test input ip6 nexthdr icmpv6 accept
add rule inet preexisting_test input tcp dport 22 accept
add table ip docker_test
add chain ip docker_test prerouting { type nat hook prerouting priority dstnat; policy accept; }
add chain ip docker_test forward { type filter hook forward priority filter; policy accept; }
add rule ip docker_test prerouting ip protocol tcp counter
add rule ip docker_test forward counter
`)
	if _, err := runner.Run(ctx, []string{"--file", "-"}, unrelatedProgram); err != nil {
		t.Fatalf("create pre-existing firewall state: %v", err)
	}
	unrelatedBefore := namespaceNFT(t, ctx, protectedNamespace, "--json", "list", "table", "inet", "preexisting_test")
	dockerBefore := namespaceNFT(t, ctx, protectedNamespace, "--json", "list", "table", "ip", "docker_test")

	stopListener := startNamespaceListener(t, ctx, protectedNamespace)
	defer stopListener()
	assertConnectivity(t, clientNamespace, true)

	implementation, err := shieldnft.NewBackendWithRunner(runner)
	if err != nil {
		t.Fatalf("create nftables backend: %v", err)
	}
	controller := integrationController(t, implementation)

	t.Run("existing SSH and unrelated rules survive", func(t *testing.T) {
		if err := controller.Reconcile(ctx, backend.DesiredState{}); err != nil {
			t.Fatalf("reconcile empty state: %v", err)
		}
		assertConnectivity(t, clientNamespace, true)
		assertRestrictedServiceBlocked(t, clientNamespace)
		assertUnrelatedUnchanged(t, ctx, protectedNamespace, unrelatedBefore)
		assertDockerUnchanged(t, ctx, protectedNamespace, dockerBefore)
	})

	t.Run("repeated apply is idempotent", func(t *testing.T) {
		state := backend.DesiredState{
			PermanentBans: []netip.Addr{netip.MustParseAddr("198.51.100.20"), netip.MustParseAddr("2001:db8:ffff::20")},
			TemporaryBans: []backend.TemporaryBan{
				{Address: netip.MustParseAddr("198.51.100.30"), ExpiresAt: time.Now().Add(time.Minute)},
				{Address: netip.MustParseAddr("2001:db8:ffff::30"), ExpiresAt: time.Now().Add(time.Minute)},
			},
		}
		if err := controller.Reconcile(ctx, state); err != nil {
			t.Fatalf("first reconcile: %v", err)
		}
		first := normalizeNFTJSON(t, namespaceNFT(t, ctx, protectedNamespace, "--json", "list", "table", "inet", "digitdojo_shield"))
		for attempt := 0; attempt < 3; attempt++ {
			if err := controller.Reconcile(ctx, state); err != nil {
				t.Fatalf("repeat reconcile %d: %v", attempt, err)
			}
			current := normalizeNFTJSON(t, namespaceNFT(t, ctx, protectedNamespace, "--json", "list", "table", "inet", "digitdojo_shield"))
			if !bytes.Equal(first, current) {
				t.Fatalf("reconcile changed normalized Shield state on attempt %d", attempt)
			}
		}
		assertUnrelatedUnchanged(t, ctx, protectedNamespace, unrelatedBefore)
		assertDockerUnchanged(t, ctx, protectedNamespace, dockerBefore)
	})

	t.Run("whitelist overrides both ban types", func(t *testing.T) {
		now := time.Now()
		state := backend.DesiredState{
			Whitelist:     []netip.Addr{netip.MustParseAddr(clientIPv4), netip.MustParseAddr(clientIPv6)},
			PermanentBans: []netip.Addr{netip.MustParseAddr(clientIPv4), netip.MustParseAddr(clientIPv6)},
			TemporaryBans: []backend.TemporaryBan{
				{Address: netip.MustParseAddr(clientIPv4), ExpiresAt: now.Add(time.Minute)},
				{Address: netip.MustParseAddr(clientIPv6), ExpiresAt: now.Add(time.Minute)},
			},
		}
		if err := controller.Reconcile(ctx, state); err != nil {
			t.Fatalf("reconcile whitelist precedence: %v", err)
		}
		assertConnectivity(t, clientNamespace, true)
		assertUnrelatedUnchanged(t, ctx, protectedNamespace, unrelatedBefore)
		assertDockerUnchanged(t, ctx, protectedNamespace, dockerBefore)
		state.Whitelist = nil
		if err := controller.Reconcile(ctx, state); err != nil {
			t.Fatalf("remove whitelist: %v", err)
		}
		assertConnectivity(t, clientNamespace, false)
	})

	t.Run("temporary bans expire in kernel", func(t *testing.T) {
		state := backend.DesiredState{TemporaryBans: []backend.TemporaryBan{
			{Address: netip.MustParseAddr(clientIPv4), ExpiresAt: time.Now().Add(2 * time.Second)},
			{Address: netip.MustParseAddr(clientIPv6), ExpiresAt: time.Now().Add(2 * time.Second)},
		}}
		if err := controller.Reconcile(ctx, state); err != nil {
			t.Fatalf("reconcile temporary bans: %v", err)
		}
		assertConnectivity(t, clientNamespace, false)
		deadline := time.Now().Add(8 * time.Second)
		for {
			current, inspectErr := implementation.Inspect(ctx)
			if inspectErr == nil && len(current.TemporaryBans) == 0 && namespaceCanConnect(clientNamespace, protectedIPv4) && namespaceCanConnect(clientNamespace, protectedIPv6) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("temporary bans did not expire: state=%+v error=%v", current, inspectErr)
			}
			time.Sleep(100 * time.Millisecond)
		}
	})

	t.Run("controller rollback restores previous Shield state", func(t *testing.T) {
		baseline := backend.DesiredState{Whitelist: []netip.Addr{netip.MustParseAddr(clientIPv4), netip.MustParseAddr(clientIPv6)}}
		if err := controller.Reconcile(ctx, baseline); err != nil {
			t.Fatalf("establish rollback baseline: %v", err)
		}
		before := normalizeNFTJSON(t, namespaceNFT(t, ctx, protectedNamespace, "--json", "list", "table", "inet", "digitdojo_shield"))
		failingBackend, createErr := shieldnft.NewBackendWithRunner(&failAfterApplyRunner{delegate: runner})
		if createErr != nil {
			t.Fatalf("create failure-injection backend: %v", createErr)
		}
		failingController := integrationController(t, failingBackend)
		err := failingController.Reconcile(ctx, backend.DesiredState{PermanentBans: []netip.Addr{netip.MustParseAddr(clientIPv4), netip.MustParseAddr(clientIPv6)}})
		if err == nil || !strings.Contains(err.Error(), "injected post-apply") {
			t.Fatalf("expected injected apply failure, got %v", err)
		}
		after := normalizeNFTJSON(t, namespaceNFT(t, ctx, protectedNamespace, "--json", "list", "table", "inet", "digitdojo_shield"))
		if !bytes.Equal(before, after) {
			t.Fatalf("rollback did not restore the prior Shield state")
		}
		assertConnectivity(t, clientNamespace, true)
		assertUnrelatedUnchanged(t, ctx, protectedNamespace, unrelatedBefore)
		assertDockerUnchanged(t, ctx, protectedNamespace, dockerBefore)
	})

	t.Run("invalid transaction commits nothing", func(t *testing.T) {
		invalid := []byte("add table inet digitdojo_atomic_probe\nthis is not valid nft syntax\n")
		if _, err := runner.Run(ctx, []string{"--file", "-"}, invalid); err == nil {
			t.Fatalf("invalid nft batch unexpectedly succeeded")
		}
		tables, err := runner.Run(ctx, []string{"list", "tables"}, nil)
		if err != nil {
			t.Fatalf("list tables: %v", err)
		}
		if bytes.Contains(tables, []byte("digitdojo_atomic_probe")) {
			t.Fatalf("kernel partially committed invalid nft batch")
		}
		assertConnectivity(t, clientNamespace, true)
	})

	t.Run("cleanup removes only Shield objects", func(t *testing.T) {
		if err := controller.Cleanup(ctx); err != nil {
			t.Fatalf("first cleanup: %v", err)
		}
		if err := controller.Cleanup(ctx); err != nil {
			t.Fatalf("idempotent cleanup: %v", err)
		}
		if err := controller.Reconcile(ctx, backend.DesiredState{}); err != nil {
			t.Fatalf("recreate Shield state before uninstall cleanup: %v", err)
		}
		cleanupScript, pathErr := filepath.Abs(filepath.Join("..", "..", "install", "firewall-cleanup.sh"))
		if pathErr != nil {
			t.Fatalf("resolve uninstall cleanup script: %v", pathErr)
		}
		runCommand(t, ctx, "ip", "netns", "exec", protectedNamespace, "bash", cleanupScript)
		runCommand(t, ctx, "ip", "netns", "exec", protectedNamespace, "bash", cleanupScript)
		tables, err := runner.Run(ctx, []string{"list", "tables"}, nil)
		if err != nil {
			t.Fatalf("list tables: %v", err)
		}
		if bytes.Contains(tables, []byte("digitdojo_shield")) {
			t.Fatalf("Shield table survived cleanup")
		}
		assertUnrelatedUnchanged(t, ctx, protectedNamespace, unrelatedBefore)
		assertDockerUnchanged(t, ctx, protectedNamespace, dockerBefore)
		assertConnectivity(t, clientNamespace, true)
	})

	t.Run("full uninstall removes staged Shield files and no other firewall objects", func(t *testing.T) {
		if err := controller.Reconcile(ctx, backend.DesiredState{}); err != nil {
			t.Fatalf("recreate Shield state before full uninstall: %v", err)
		}
		uninstallScript, pathErr := filepath.Abs(filepath.Join("..", "..", "install", "uninstall.sh"))
		if pathErr != nil {
			t.Fatalf("resolve uninstall script: %v", pathErr)
		}
		runStagedUninstall(t, ctx, protectedNamespace, uninstallScript)
		tables, err := runner.Run(ctx, []string{"list", "tables"}, nil)
		if err != nil {
			t.Fatalf("list tables after full uninstall: %v", err)
		}
		if bytes.Contains(tables, []byte("digitdojo_shield")) {
			t.Fatalf("Shield table survived full uninstall")
		}
		assertUnrelatedUnchanged(t, ctx, protectedNamespace, unrelatedBefore)
		assertDockerUnchanged(t, ctx, protectedNamespace, dockerBefore)
		assertConnectivity(t, clientNamespace, true)
	})
}

func TestNamespaceListener(t *testing.T) {
	if os.Getenv("SHIELD_TEST_LISTENER") != "1" {
		return
	}
	listeners := make([]net.Listener, 0, 2)
	for _, spec := range namespaceListenerSpecs {
		listener, err := net.Listen(spec.network, spec.address)
		if err != nil {
			t.Fatalf("listen on %s %s: %v", spec.network, spec.address, err)
		}
		listeners = append(listeners, listener)
	}
	fmt.Println("READY")
	for _, listener := range listeners {
		go func(listener net.Listener) {
			for {
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				_ = connection.Close()
			}
		}(listener)
	}
	select {}
}

func TestNamespaceListenerUsesSeparateIPv4AndIPv6Sockets(t *testing.T) {
	if len(namespaceListenerSpecs) != 4 {
		t.Fatalf("expected separate IPv4 and IPv6 listener specifications for both test ports, got %+v", namespaceListenerSpecs)
	}
	if namespaceListenerSpecs[0] != (listenerSpec{network: "tcp4", address: "0.0.0.0:22"}) {
		t.Fatalf("unexpected IPv4 listener specification: %+v", namespaceListenerSpecs[0])
	}
	if namespaceListenerSpecs[1] != (listenerSpec{network: "tcp6", address: "[::]:22"}) {
		t.Fatalf("unexpected IPv6 listener specification: %+v", namespaceListenerSpecs[1])
	}
	if namespaceListenerSpecs[2] != (listenerSpec{network: "tcp4", address: "0.0.0.0:8080"}) {
		t.Fatalf("unexpected restricted IPv4 listener specification: %+v", namespaceListenerSpecs[2])
	}
	if namespaceListenerSpecs[3] != (listenerSpec{network: "tcp6", address: "[::]:8080"}) {
		t.Fatalf("unexpected restricted IPv6 listener specification: %+v", namespaceListenerSpecs[3])
	}
}

func TestNamespaceDialHelper(t *testing.T) {
	address := os.Getenv("SHIELD_TEST_DIAL")
	if address == "" {
		return
	}
	connection, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	_ = connection.Close()
}

func integrationController(t *testing.T, implementation backend.Backend) *Controller {
	t.Helper()
	registry, err := NewRegistry(Registration{
		Probe:   integrationProbe{},
		Factory: func() (backend.Backend, error) { return implementation, nil },
	})
	if err != nil {
		t.Fatalf("create integration registry: %v", err)
	}
	controller, err := newController(registry, string(backend.NFTables), true)
	if err != nil {
		t.Fatalf("create integration controller: %v", err)
	}
	return controller
}

func requireLinuxFirewallEnvironment(t *testing.T) {
	t.Helper()
	if err := shieldnft.CheckIntegrationEnvironment(); err != nil {
		t.Fatalf("Linux nftables integration preflight failed: %v", err)
	}
	for _, command := range []string{"ip", "nft"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Fatalf("required command %s is unavailable: %v", command, err)
		}
	}
	nftPath, err := exec.LookPath("nft")
	if err != nil {
		t.Fatalf("locate nft for version preflight: %v", err)
	}
	if version, err := shieldnft.CheckNFTVersion(context.Background(), nftPath); err != nil {
		t.Fatalf("nftables version preflight failed: %v", err)
	} else {
		t.Logf("nftables %s detected", version)
	}
}

func setupNamespaces(t *testing.T, ctx context.Context, protected, client, protectedLink, clientLink string) {
	t.Helper()
	runCommand(t, ctx, "ip", "netns", "add", protected)
	runCommand(t, ctx, "ip", "netns", "add", client)
	runCommand(t, ctx, "ip", "link", "add", protectedLink, "type", "veth", "peer", "name", clientLink)
	runCommand(t, ctx, "ip", "link", "set", protectedLink, "netns", protected)
	runCommand(t, ctx, "ip", "link", "set", clientLink, "netns", client)
	for _, namespace := range []string{protected, client} {
		runCommand(t, ctx, "ip", "-n", namespace, "link", "set", "lo", "up")
	}
	runCommand(t, ctx, "ip", "-n", protected, "addr", "add", "192.0.2.1/24", "dev", protectedLink)
	runCommand(t, ctx, "ip", "-n", client, "addr", "add", "192.0.2.2/24", "dev", clientLink)
	runCommand(t, ctx, "ip", "-n", protected, "-6", "addr", "add", "2001:db8:1::1/64", "dev", protectedLink, "nodad")
	runCommand(t, ctx, "ip", "-n", client, "-6", "addr", "add", "2001:db8:1::2/64", "dev", clientLink, "nodad")
	runCommand(t, ctx, "ip", "-n", protected, "link", "set", protectedLink, "up")
	runCommand(t, ctx, "ip", "-n", client, "link", "set", clientLink, "up")
}

func startNamespaceListener(t *testing.T, ctx context.Context, namespace string) func() {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test executable: %v", err)
	}
	command := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, executable, "-test.run=^TestNamespaceListener$")
	command.Env = append(os.Environ(), "SHIELD_TEST_LISTENER=1")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("listener stdout: %v", err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start namespace listener: %v", err)
	}
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			ready <- scanner.Text()
		}
	}()
	select {
	case line := <-ready:
		if line != "READY" {
			t.Fatalf("unexpected listener readiness output %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("namespace listener did not become ready")
	}
	return func() {
		if command.Process != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}
}

func assertConnectivity(t *testing.T, namespace string, expected bool) {
	t.Helper()
	for _, address := range []string{protectedIPv4, protectedIPv6} {
		if actual := namespaceCanConnect(namespace, address); actual != expected {
			t.Fatalf("connectivity to %s: got %t, expected %t", address, actual, expected)
		}
	}
}

func assertRestrictedServiceBlocked(t *testing.T, namespace string) {
	t.Helper()
	for _, address := range []string{blockedIPv4, blockedIPv6} {
		if namespaceCanConnect(namespace, address) {
			t.Fatalf("restrictive host policy no longer blocks %s", address)
		}
	}
}

func namespaceCanConnect(namespace, address string) bool {
	executable, err := os.Executable()
	if err != nil {
		return false
	}
	command := exec.Command("ip", "netns", "exec", namespace, executable, "-test.run=^TestNamespaceDialHelper$")
	command.Env = append(os.Environ(), "SHIELD_TEST_DIAL="+address)
	return command.Run() == nil
}

func assertUnrelatedUnchanged(t *testing.T, ctx context.Context, namespace string, expected []byte) {
	t.Helper()
	actual := namespaceNFT(t, ctx, namespace, "--json", "list", "table", "inet", "preexisting_test")
	if !bytes.Equal(normalizeNFTJSON(t, expected), normalizeNFTJSON(t, actual)) {
		t.Fatalf("unrelated nftables state changed")
	}
}

func assertDockerUnchanged(t *testing.T, ctx context.Context, namespace string, expected []byte) {
	t.Helper()
	actual := namespaceNFT(t, ctx, namespace, "--json", "list", "table", "ip", "docker_test")
	if !bytes.Equal(normalizeNFTJSON(t, expected), normalizeNFTJSON(t, actual)) {
		t.Fatalf("Docker-style nftables state changed")
	}
}

func runStagedUninstall(t *testing.T, ctx context.Context, namespace, uninstallScript string) {
	t.Helper()
	// A private mount namespace prevents the test from touching the runner's
	// /etc, /usr/local, and /var while exercising the production uninstall script.
	const script = `set -euo pipefail
mount --make-rprivate /
mount -t tmpfs tmpfs /etc
mount -t tmpfs tmpfs /usr/local
mount -t tmpfs tmpfs /var
mkdir -p /etc/systemd/system /etc/digitdojo-shield /var/log/digitdojo-shield /var/lib/digitdojo-shield /usr/local/bin
touch /etc/systemd/system/digitdojo-shield.service /etc/digitdojo-shield/config.yml /var/log/digitdojo-shield/shield.log /var/lib/digitdojo-shield/state.json /usr/local/bin/shield /usr/local/bin/shieldd
bash "$1"
test ! -e /etc/systemd/system/digitdojo-shield.service
test ! -e /etc/digitdojo-shield
test ! -e /var/log/digitdojo-shield
test ! -e /var/lib/digitdojo-shield
test ! -e /usr/local/bin/shield
test ! -e /usr/local/bin/shieldd
`
	runCommand(t, ctx, "ip", "netns", "exec", namespace, "unshare", "--mount", "--propagation", "private", "bash", "-ceu", script, "shield-uninstall", uninstallScript)
}

func normalizeNFTJSON(t *testing.T, input []byte) []byte {
	t.Helper()
	var value any
	if err := json.Unmarshal(input, &value); err != nil {
		t.Fatalf("decode nft JSON: %v\n%s", err, input)
	}
	stripVolatileNFTFields(value)
	result, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("normalize nft JSON: %v", err)
	}
	return result
}

func stripVolatileNFTFields(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for _, key := range []string{"handle", "timeout", "expires", "packets", "bytes"} {
			delete(typed, key)
		}
		for _, child := range typed {
			stripVolatileNFTFields(child)
		}
	case []any:
		for _, child := range typed {
			stripVolatileNFTFields(child)
		}
	}
}

func namespaceNFT(t *testing.T, ctx context.Context, namespace string, args ...string) []byte {
	t.Helper()
	return commandOutput(t, ctx, nil, "ip", append([]string{"netns", "exec", namespace, "nft"}, args...)...)
}

func runCommand(t *testing.T, ctx context.Context, command string, args ...string) {
	t.Helper()
	_ = commandOutput(t, ctx, nil, command, args...)
}

func commandOutput(t *testing.T, ctx context.Context, input []byte, command string, args ...string) []byte {
	t.Helper()
	process := exec.CommandContext(ctx, command, args...)
	process.Stdin = bytes.NewReader(input)
	output, err := process.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v: %s", command, args, err, bytes.TrimSpace(output))
	}
	return output
}

func commandBestEffort(command string, args ...string) {
	_ = exec.Command(command, args...).Run()
}

func namespaceName(prefix string) string {
	return prefix + strconv.Itoa(os.Getpid())
}

func linkName(prefix string) string {
	return prefix + strconv.Itoa(os.Getpid()%100000)
}
