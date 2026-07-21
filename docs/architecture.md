# DigitDojo Shield architecture

DigitDojo Shield has two executables: the short-lived `shield` administrative
CLI and the Linux `shieldd` daemon. `shieldd` loads and validates configuration,
constructs one `internal/app.Application`, and transfers signal-driven lifecycle
ownership to it.

## Runtime ownership

The application owns one instance of every long-lived subsystem:

- structured logger;
- firewall manager;
- versioned file-backed state and shared allow/block managers;
- detector sampler and detection engine;
- monitor snapshot;
- event bus;
- alert service;
- REST API server.

The API receives the same list managers and statistics provider owned by the
application. It does not construct separate production state. Detector samples
update the monitor snapshot and publish events. Events are logged, and runtime
errors are delivered to configured HTTPS webhook alerts. Attack alerts remain
disabled until detector accuracy is corrected.

## Startup and shutdown

1. `shieldd` loads the configured file and exits on any error.
2. The application secures its log and state directories.
3. Persistent state is validated and restored.
4. Alert settings and API dependencies are validated.
5. The optional API listener is bound before startup succeeds.
6. The detector loop starts and a `RuntimeStarted` event is recorded.
7. SIGINT, SIGTERM, or an API serving failure begins shutdown.
8. API requests are drained, the detector is stopped, a final lifecycle event
   is recorded, and the log file is synchronized and closed.

## Current enforcement boundary

Firewall contracts live in `internal/firewall/backend`. The nftables and
iptables packages independently detect their userspace prerequisites. A registry
distinguishes command detection from implementation readiness, and the
controller owns serialized reconciliation and rollback orchestration.

The default registry contains the real nftables backend factory and retains
detection-only iptables support. The nftables implementation owns only the
`inet digitdojo_shield` table and uses typed snapshots, checked atomic batches,
and controller-managed rollback. The exported controller constructor still
cannot enable enforcement, so the runtime reports
`firewall_enforced: false` and rejects blacklist, whitelist, and unban API
mutations with HTTP 503. The Linux release gate is documented in
`firewall-integration-testing.md`.

DigitDojo Shield remains host-based defense-in-depth and is not a replacement
for upstream DDoS filtering.
