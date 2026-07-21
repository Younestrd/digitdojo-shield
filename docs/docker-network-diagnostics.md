# Docker published-port diagnostics

Run this unchanged on a GitHub-hosted Ubuntu 24.04 runner or a clean Ubuntu
24.04 VPS as root:

```sh
bash scripts/docker-network-diagnostics.sh | tee docker-network-diagnostics.log
```

It creates an isolated Docker bridge and nginx container with a dynamically
published TCP port, then captures `docker info`, Docker network/container state,
addresses, routes, nftables, iptables-save when installed, and listening
sockets. It probes the published service from localhost, a second real Docker
bridge container, and an external Linux network namespace connected by veth.

The script cleans up only the Docker network/container and namespace/veth names
it created. A nonzero result means at least one path failed; retain the complete
log. Do not attribute a failure to Shield unless the same capture has been run
both before and after an explicit Shield reconciliation.
