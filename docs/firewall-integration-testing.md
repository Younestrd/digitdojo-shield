# Firewall Linux integration test suite

Firewall enforcement must remain disabled until this suite passes against a
real Linux kernel. The suite is implemented in
`internal/firewall/nftables_integration_test.go` and configured in
`.github/workflows/linux-firewall-integration.yml`. Unit tests cannot prove
nftables transaction semantics or packet behavior.

## Runner requirements

The runner must provide:

- a Linux kernel with `nf_tables` support;
- nftables userspace version 1.0.9 or newer (`nft --version`);
- `nft` and `ip` from iproute2;
- Go matching the version declared by the module;
- root in an isolated VM, or a privileged container with `CAP_SYS_ADMIN` and
  `CAP_NET_ADMIN`;
- permission to create network namespaces and veth pairs.

The runtime backend requires Linux and `CAP_NET_ADMIN`. The namespace suite
also requires `CAP_SYS_ADMIN`. Its preflight reports each missing capability
and explains whether it blocks rule mutation or namespace isolation.

The suite uses the build constraint `linux && integration` and runs with:

```sh
go test -count=1 -tags=integration -v ./internal/firewall/nftables
```

It must fail, rather than skip, when explicitly invoked without required
commands, privileges, kernel support, or namespace isolation.

## Isolation model

Each test creates uniquely named client and protected-host namespaces joined by
a veth pair. IPv4 and IPv6 addresses are assigned to both ends. The nftables
backend is executed inside the protected-host namespace by re-executing the Go
test binary through `ip netns exec`; it must never operate in the runner's host
namespace.

The harness records the runner's host ruleset before and after the suite and
requires byte-equivalent normalized nftables JSON. Cleanup is registered before
the first namespace mutation and removes only namespaces and veth devices whose
unique names were created by that test.

Inside the protected namespace, every test first creates an unrelated
`inet preexisting_test` table. Its normalized JSON is recorded before Shield
operations and compared afterward. Shield may own only
`inet digitdojo_shield`.

## Required tests

### Existing SSH access is preserved

1. Create a pre-existing input chain that accepts established traffic and TCP
   destination port 22.
2. Start a test TCP listener on port 22 inside the protected namespace.
3. Connect from both IPv4 and IPv6 client addresses before reconciliation.
4. Reconcile an empty Shield state and connect again.
5. Require every connection to succeed and require the unrelated table JSON to
   remain unchanged.

The listener validates transport reachability; it does not simulate the SSH
protocol.

### Unrelated rules remain untouched

1. Populate the unrelated table with named sets, counters, and multiple rules.
2. Record `nft -j list table inet preexisting_test` after removing volatile
   counter values and handles.
3. Reconcile several different Shield states.
4. Compare the unrelated table after every operation and after cleanup.

### Atomic failure and rollback

1. Reconcile a known Shield state and snapshot its normalized JSON.
2. Use an integration-test executor wrapper around the real nft executor that
   allows the real atomic batch to run, then injects a post-apply verification
   failure.
3. Require the controller to restore the pre-operation snapshot using its
   independent rollback context.
4. Compare the restored table JSON with the original and verify packet behavior.
5. Repeat with a deliberately invalid nft batch and prove the kernel committed
   none of that batch.

The wrapper may inject errors only around real kernel operations; it must not
replace the nftables backend with an in-memory implementation.

### Idempotent reconciliation

1. Reconcile a mixed IPv4/IPv6 state.
2. Record normalized JSON excluding handles, counters, and remaining timeout
   values.
3. Reconcile the identical state repeatedly.
4. Require identical normalized state, one owned table, one instance of each
   chain/set, and unchanged packet behavior.

### Temporary-ban expiry

1. Add IPv4 and IPv6 client addresses to temporary sets with a two-second TTL.
2. Require new connections to be dropped while entries exist.
3. Poll nftables and connectivity with a bounded deadline.
4. Require both elements to disappear and connectivity to recover without a
   reconciliation call.

### Whitelist precedence

1. Place each client address simultaneously in the whitelist, permanent-ban,
   and temporary-ban sets.
2. Require IPv4 and IPv6 connections to succeed.
3. Remove the whitelist entries while leaving bans intact.
4. Require new connections to fail.

### Cleanup ownership

1. Create the unrelated table and a populated Shield table.
2. Invoke backend cleanup twice to prove idempotency.
3. Require `inet digitdojo_shield` to be absent.
4. Require the unrelated table and host-namespace ruleset to remain unchanged.

## State normalization and diagnostics

Comparisons use `nft -j` output. The test normalizer removes only kernel-assigned
handles, counter packet/byte values, and element timeout/remaining-TTL values
that naturally decrease when an absolute expiry is reconciled.
It must retain table, chain, set, rule, address-family, hook, priority, policy,
and expression data.

On failure, the harness prints namespace names, both namespace addresses,
normalized before/after JSON, `nft list ruleset`, command stderr, and packet-test
results. Namespaces are still cleaned automatically unless an explicit local
debug environment variable requests preservation; CI must never preserve them.

## Enforcement release gate

An exported enforcement-enabled controller constructor may be added only after:

1. every test above passes on the supported minimum and current Linux kernels;
2. the suite passes with the supported nft userspace versions;
3. a failure run proves the runner's host ruleset is unchanged;
4. rollback and cleanup tests pass repeatedly under `go test -count=20` (CI
   currently runs the complete suite five times per execution);
5. test artifacts are retained in CI for review.

Until that gate is met, the nftables factory is registered for capability and
inspection purposes, but the exported controller cannot mutate firewall state
and the runtime reports `firewall_enforced: false`.
