# Developer Handoff: DigitDojo Shield

> Historical note: subsystem completion claims below predate the architecture
> audit and must not be treated as current release status. See `architecture.md`
> and `firewall-integration-testing.md` for the current runtime and firewall
> enforcement boundary.

## Scope and intent

DigitDojo Shield is a host-based Linux hardening and mitigation platform for game hosting and similar infrastructure. The implementation is intentionally defensive, operationally safe, and deployment-oriented rather than a replacement for upstream DDoS protection.

The codebase is already structured as a modular Go project with a CLI entrypoint and isolated subsystems for configuration, detection, firewalling, syscall hardening, monitoring, alerting, logging, and API management.

## 1. Current project architecture

### Runtime shape
- The CLI entrypoint in [cmd/shield/main.go](cmd/shield/main.go) parses commands and dispatches to subsystems.
- Configuration is centralized in [internal/config/config.go](internal/config/config.go), [internal/config/yaml.go](internal/config/yaml.go), and [internal/config/reload.go](internal/config/reload.go).
- Detector logic lives in [internal/detector/detector.go](internal/detector/detector.go) and [internal/detector/daemon.go](internal/detector/daemon.go).
- Firewall contracts, the disabled controller, and the backend registry live in
  [internal/firewall](internal/firewall); the real nftables implementation and
  the detection-only iptables package remain isolated backend packages.
- Kernel hardening is handled in [internal/sysctl/sysctl.go](internal/sysctl/sysctl.go).
- Internal signaling and lifecycle coordination use [internal/events/events.go](internal/events/events.go).
- Structured logging is in [internal/logger/structured.go](internal/logger/structured.go) and [internal/logger/logger.go](internal/logger/logger.go).
- Monitoring and snapshots are assembled in [internal/monitor/monitor.go](internal/monitor/monitor.go).
- Alerts are emitted via [internal/alerts/alerts.go](internal/alerts/alerts.go).
- The management API is in [internal/api/api.go](internal/api/api.go).
- IP allow/block management is in [internal/blacklist/blacklist.go](internal/blacklist/blacklist.go) and [internal/whitelist/whitelist.go](internal/whitelist/whitelist.go).

### Design assumptions
- This is a host-based mitigation tool for Linux, not a full upstream network scrubbing platform.
- The implementation should prioritize correctness, rollback safety, and operational clarity over feature breadth.
- The project is intended to be deployed on privileged Linux hosts, so conservative failure handling and rollback semantics are mandatory.

## 2. Completed subsystems and verification status

### Configuration subsystem
Status: completed and verified.
- Hardened validation for malformed config, unsafe bind addresses, and unsafe paths.
- Added reload-oriented behavior and stricter YAML parsing.
- Verified by package tests in [internal/config](internal/config).

### Detector subsystem
Status: completed and verified.
- Added host metric sampling from Linux proc interfaces and conntrack data.
- Added attack evaluation logic.
- Hardened daemon lifecycle behavior with start/stop/shutdown protection, context awareness, panic recovery, and regression tests.
- Verified by: `go test ./internal/detector` and `go vet ./internal/detector`.

### Firewall subsystem
Status: nftables implementation complete in code; production enforcement disabled pending CI evidence.
- Added an explicit backend contract, registry, capability probes, and rollback controller.
- The default registry includes the nftables factory, but the exported controller cannot mutate rules.
- Added atomic ruleset replacement, typed snapshots, IPv4/IPv6 sets, expiring bans, whitelist precedence, and owned-table cleanup.
- Unit orchestration is verified; kernel behavior remains unverified until the privileged workflow succeeds.
- The required Linux suite is implemented under the `linux && integration` build tags and configured in `.github/workflows/linux-firewall-integration.yml`.

### Sysctl hardening subsystem
Status: completed and verified.
- Added safe kernel parameter changes with backup and restore semantics.
- Verified by package tests in [internal/sysctl](internal/sysctl).

### Events and logger subsystems
Status: completed and verified.
- Added internal event distribution and structured logging.
- Verified by package tests in [internal/events](internal/events) and [internal/logger](internal/logger).

### Monitor subsystem
Status: completed and verified.
- Added monitoring aggregation and snapshot composition.
- Verified by package tests in [internal/monitor](internal/monitor).

### API subsystem
Status: completed and verified.
- Added token-based auth, request-body limits, rate limiting, and graceful shutdown support.
- Verified by package tests in [internal/api](internal/api).

### Allow/block list subsystems
Status: completed and verified.
- Added allow/block list behavior with tests around core behavior and concurrency safety.
- Verified by package tests in [internal/blacklist](internal/blacklist) and [internal/whitelist](internal/whitelist).

### Installer and packaging assets
Status: present, but not the main focus of the current hardening pass.
- Installer scripts are in [install.sh](install.sh) and [install/uninstall.sh](install/uninstall.sh).
- These should be validated on a Linux host, not assumed correct purely from static review.

## 3. Remaining subsystems in priority order

1. Production deployment integration
   - Ensure the CLI, installer, and service entrypoints are operational on a real Linux host.
   - Validate systemd integration and service ownership assumptions.

2. Runtime hardening around external Linux dependencies
   - Confirm behavior under real procfs, nftables/iptables availability, and service account constraints.
   - Validate failure behavior when commands are unavailable or permissions are insufficient.

3. End-to-end operational wiring
   - Connect detector output, monitor snapshots, firewall actions, and alerts into a coherent runtime path.
   - Confirm the runtime can recover cleanly from config reloads and partial subsystem failures.

4. Documentation and rollout readiness
   - Finalize operational guidance, deployment assumptions, and installation notes for real environments.

## 4. Production decisions made so far and rationale

### Decision: prioritize rollback-safe behavior over feature completeness
Reasoning: this platform is intended to run on privileged hosts, so partial application of firewall or sysctl changes is unacceptable. Backup and restore semantics were chosen as the default design.

### Decision: validate configuration aggressively before runtime use
Reasoning: misconfiguration on a host-based security tool can cause service disruption or ineffective protection. Strict validation is preferable to permissive parsing.

### Decision: prefer explicit lifecycle control over implicit goroutine handling
Reasoning: daemons, sampling loops, and shutdown paths must be deterministic under stop and timeout conditions. This drove the hardening around context cancellation, WaitGroup usage, and panic recovery.

### Decision: treat API access as privileged and rate-limit it
Reasoning: management endpoints should not become a denial-of-service vector or an uncontrolled control surface.

### Decision: keep the project as defense-in-depth rather than a replacement for upstream DDoS mitigation
Reasoning: this is a practical host-level mitigation layer with realistic scope and operational constraints.

### Decision: rely on Linux-native interfaces where possible
Reasoning: the runtime should collect metrics from procfs and host networking interfaces rather than inventing a synthetic abstraction.

## 5. Files modified in each subsystem

### CLI and entrypoints
- [cmd/shield/main.go](cmd/shield/main.go)

### Configuration
- [internal/config/config.go](internal/config/config.go)
- [internal/config/yaml.go](internal/config/yaml.go)
- [internal/config/reload.go](internal/config/reload.go)
- [internal/config/config_test.go](internal/config/config_test.go)
- [internal/config/config_hardening_test.go](internal/config/config_hardening_test.go)
- [internal/config/reload_test.go](internal/config/reload_test.go)
- [internal/config/yaml_test.go](internal/config/yaml_test.go)

### Detector and daemon lifecycle
- [internal/detector/detector.go](internal/detector/detector.go)
- [internal/detector/daemon.go](internal/detector/daemon.go)
- [internal/detector/daemon_test.go](internal/detector/daemon_test.go)
- [internal/detector/daemon_lifecycle_test.go](internal/detector/daemon_lifecycle_test.go)
- [internal/detector/detector_test.go](internal/detector/detector_test.go)

### Firewall
- [internal/firewall/controller.go](internal/firewall/controller.go)
- [internal/firewall/registry.go](internal/firewall/registry.go)
- [internal/firewall/backend/backend.go](internal/firewall/backend/backend.go)
- [internal/firewall/nftables/probe.go](internal/firewall/nftables/probe.go)
- [internal/firewall/iptables/probe.go](internal/firewall/iptables/probe.go)

### Sysctl
- [internal/sysctl/sysctl.go](internal/sysctl/sysctl.go)
- [internal/sysctl/sysctl_test.go](internal/sysctl/sysctl_test.go)

### Events and logging
- [internal/events/events.go](internal/events/events.go)
- [internal/events/events_test.go](internal/events/events_test.go)
- [internal/logger/logger.go](internal/logger/logger.go)
- [internal/logger/structured.go](internal/logger/structured.go)
- [internal/logger/structured_test.go](internal/logger/structured_test.go)

### Monitor
- [internal/monitor/monitor.go](internal/monitor/monitor.go)
- [internal/monitor/monitor_test.go](internal/monitor/monitor_test.go)

### Alerts
- [internal/alerts/alerts.go](internal/alerts/alerts.go)

### API
- [internal/api/api.go](internal/api/api.go)
- [internal/api/api_test.go](internal/api/api_test.go)
- [internal/api/api_stress_test.go](internal/api/api_stress_test.go)
- [internal/api/api_rate_limiter_test.go](internal/api/api_rate_limiter_test.go)

### Allow/block lists
- [internal/blacklist/blacklist.go](internal/blacklist/blacklist.go)
- [internal/blacklist/blacklist_test.go](internal/blacklist/blacklist_test.go)
- [internal/blacklist/blacklist_stress_test.go](internal/blacklist/blacklist_stress_test.go)
- [internal/whitelist/whitelist.go](internal/whitelist/whitelist.go)
- [internal/whitelist/whitelist_test.go](internal/whitelist/whitelist_test.go)

### Installer
- [install.sh](install.sh)
- [install/uninstall.sh](install/uninstall.sh)

## 6. Outstanding technical debt and known limitations

- The project has not yet been validated on a real Linux deployment host with actual firewall backends and service permissions.
- The installer and service integration should be validated in a real environment rather than assumed correct from source review.
- The detector still depends on Linux-specific files such as procfs and host networking tools; behavior on non-Linux environments is not a primary focus.
- The implementation uses a host-based mitigation model and is not intended to replace upstream DDoS defense.
- The current environment does not provide a verified race-test execution path for cgo-dependent code, so concurrency validation remains partially environment-limited.

## 7. Current test coverage and verification results

Fresh verification was run in the workspace with:
- `go test ./...`
- `go vet ./...`
- `go test -cover ./...`

Observed results:
- All package tests passed.
- `go vet` completed without errors.
- Coverage summary from the latest run:
  - [internal/events](internal/events): 100.0%
  - [internal/monitor](internal/monitor): 83.3%
  - [internal/api](internal/api): 45.2%
  - [internal/config](internal/config): 62.0%
  - [internal/detector](internal/detector): 54.3%
  - [internal/firewall](internal/firewall): 50.3%
  - [internal/sysctl](internal/sysctl): 22.4%
  - [internal/logger](internal/logger): 28.3%
  - [internal/blacklist](internal/blacklist): 61.5%
  - [internal/whitelist](internal/whitelist): 69.6%

## 8. Remaining production risks

- A real deployment could expose assumptions around permissions, firewall backend availability, and procfs compatibility.
- Long-running sampling or subsystem operations could still trigger timeout behavior during shutdown if they do not return promptly.
- The daemon lifecycle is now hardened, but integration with real service management and signal delivery remains to be proven on a real Linux host.
- Installer and service startup behavior must be tested in the target environment rather than assumed from repository inspection.

## 9. Exact next task to begin with

Begin with deployment and runtime integration for the detector/firewall path on a Linux host.

Concretely:
1. Validate the CLI entrypoint and installer on a real Linux environment.
2. Confirm the daemon starts, reports metrics, and shuts down cleanly under actual service conditions.
3. Verify the firewall manager can apply and rollback rules in the target environment without breaking host networking.

Do not start with unrelated refactors or new features. The next work should stay within the real deployment path.

## 10. Checklist of requirements for the next subsystem

When continuing, maintain these requirements:
- Preserve rollback-safe behavior for privileged operations.
- Do not introduce placeholder logic or cosmetic-only behavior.
- Keep lifecycle operations deterministic under start/stop/shutdown.
- Ensure any new code is covered by tests that exercise real failure modes.
- Prefer explicit, auditable behavior over hidden concurrency magic.
- Do not assume Linux tooling is present without checking for it in the runtime environment.
- Keep error paths observable and structured.

## 11. Assumptions that must remain consistent across future work

- The project remains a Linux host-based mitigation tool, not a cloud scrubbing service.
- Privileged operations must be safe to rollback or fail closed.
- Configuration must be validated before use and never trusted blindly.
- Daemon lifecycle behavior must remain deterministic and not leak goroutines, contexts, or resources.
- Future work should maintain the current production posture: correctness first, breadth second.
