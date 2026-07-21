# Docker Engine firewall integration testing

This suite is real Linux-kernel and Docker Engine coverage. It does not use a
synthetic Docker nftables table as a substitute for Docker networking.

The GitHub Actions Ubuntu 24.04 workflow installs `docker.io`, starts Docker,
and runs `TestDockerEngineNFTablesIntegration` with
`SHIELD_DOCKER_INTEGRATION=1`. The test creates a custom bridge network and an
nginx container with a loopback-published port. It then verifies:

- Docker creates observable firewall objects for the real published port;
- the published port works before and after Shield reconciliation;
- Docker restart, stop, and start preserve the expected networking behavior;
- Shield permanent and temporary state updates do not alter any non-Shield
  nftables object;
- staged production uninstall removes only Shield firewall state and leaves the
  published container reachable; and
- removing test resources restores the host nftables ruleset to its pre-test
  normalized state.

The test runs only in the privileged CI workflow. It deliberately fails if the
Docker daemon is unavailable or published-port setup does not result in
observable Docker-managed nftables state.

Passing this suite establishes Docker Engine coexistence only for the exact
Ubuntu runner image and Docker package tested by the retained CI artifact. It
does not establish Pterodactyl/Wings, game-server, IPv6-published-port, or
other-distribution compatibility. Firewall enforcement remains disabled until
those separate gates are proven.
