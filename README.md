# DigitDojo Shield

DigitDojo Shield is a developing host-based Linux security daemon for game
hosting and similar infrastructure. The current release provides the runtime
foundation and an nftables backend behind a closed release gate; kernel
enforcement and accurate rate-based detection are not yet production-ready. It
does not claim to stop upstream DDoS attacks.

## Features

- Long-running Linux daemon with deterministic startup and shutdown
- Central lifecycle ownership for all runtime subsystems
- Versioned, file-backed shared allow/block state
- Authenticated optional REST API backed by the daemon's shared state
- Linux host sampling connected to monitoring, events, logging, and alerts
- Atomic, Shield-owned nftables backend with a closed enforcement safety boundary

The `firewall.backend` setting accepts `auto`, `nftables`, `iptables`, or a
future registered backend name. Selection does not enable enforcement. The
runtime reports separately whether tooling was detected and whether an
implementation is registered.

## Getting started

1. Build the CLI and daemon:
   - `go build ./cmd/shield`
   - `go build ./cmd/shieldd`
2. Run the daemon on Linux:
   - `./shieldd -config /etc/digitdojo-shield/config.yml`
3. Install on a systemd-based Linux host:
   - `bash install.sh`

`shieldd` owns the detector loop, monitor snapshot, event bus, logger, alert
delivery, persistent list state, firewall manager, and optional REST API. It
shuts these resources down when it receives SIGINT or SIGTERM.

The current runtime does not enable firewall mutations. API blacklist,
whitelist, and unban requests return HTTP 503 until the privileged Linux
integration workflow passes and the release gate is reviewed. This prevents
administrative state from being presented as active protection before kernel
behavior is verified.

## Architecture

- `cmd/shield` contains the administrative CLI entrypoint
- `cmd/shieldd` contains the Linux daemon entrypoint
- `internal/app` owns the central runtime lifecycle
- `internal/storage` owns versioned persistent list state
- `internal/config` handles configuration validation and hot reload
- `internal/detector` provides host metric sampling and attack evaluation
- `internal/firewall` implements the backup/rollback firewall engine
- `internal/firewall/nftables` owns the dedicated nftables table implementation
- `internal/sysctl` manages safe kernel hardening values
- `internal/events` provides the internal event bus
- `internal/logger` provides structured logging

## Production status

The runtime lifecycle is implemented, but the project is not production-ready.
Firewall mutation is deliberately disabled, and the existing detector values
still require correction before they can drive enforcement decisions.

The privileged namespace suite is run by
`.github/workflows/linux-firewall-integration.yml` on Ubuntu 24.04. It requires
root and `CAP_NET_ADMIN`; compiling that suite on another platform does not
count as kernel verification.

The nftables backend requires nftables 1.0.9 or newer and Linux
`CAP_NET_ADMIN`. The namespace integration suite also requires
`CAP_SYS_ADMIN`; missing prerequisites are reported before any firewall command
is attempted.

## Verification

Verified locally with:
- `go test ./...`
- `go build ./cmd/shield`
- `go vet ./...`
- `go test -cover ./...`

The race-enabled test pass is currently blocked in this environment because Go's cgo path requires a working C compiler (`gcc` was not available).
