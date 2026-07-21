# Firewall enforcement gate review

Status: **closed**. The public firewall controller must remain enforcement-disabled.

## Evidence reviewed

GitHub Actions run [#4](https://github.com/Younestrd/digitdojo-shield/actions/runs/29841643232), for commit `588d75562895b0094f6a9d17be01e8f9a217161b`, completed successfully on the GitHub-hosted `ubuntu-24.04` runner. Its `nftables` job installed nftables and iproute2, passed the capability preflight, unit tests, static analysis, and `go test -tags=integration -count=20 -v ./internal/firewall`. The retained `firewall-integration-29841643232` artifact is available until 2026-10-19.

This evidence proves the original namespace suite only. It is not evidence for Docker, Pterodactyl, other distributions, a production host's existing policy, or the full uninstall script unless the corresponding tests below are present in the successful run.

## Formal activation checklist

Every item must be checked by a retained, successful Linux CI artifact before an enforcement-enabled constructor is considered.

- [x] Dedicated `inet digitdojo_shield` table only; unrelated table preservation in the original Ubuntu 24.04 20-run suite.
- [x] Atomic nft batch validation and no partial commit for an invalid batch.
- [x] Controller rollback restores its Shield-only snapshot after a post-apply failure.
- [x] IPv4 and IPv6 permanent and temporary ban packet behavior.
- [x] Whitelist precedence over Shield permanent and temporary ban sets.
- [x] Temporary set elements expire in the kernel without reconciliation.
- [x] Idempotent reconcile and cleanup in the original 20-run suite.
- [ ] Restrictive pre-existing host firewall coexistence, including non-SSH traffic; added to the suite but not yet run in CI.
- [ ] Docker-style nftables NAT/forward table preservation; added to the suite but not yet run in CI.
- [ ] Full `install/uninstall.sh` execution in an isolated Linux mount and network namespace; added to the suite but not yet run in CI.
- [ ] Ubuntu version matrix: supported minimum and current releases.
- [ ] Debian version matrix: supported minimum and current releases.
- [ ] Real Docker Engine integration (container publishing, NAT, bridge networking, and restart) on a supported host.
- [ ] Pterodactyl Wings integration using a documented supported version and representative game-server traffic.
- [ ] Operational rollout plan: backup, canary, explicit operator confirmation, health checks, and tested recovery procedure.
- [ ] Independent security review of rule priority, verdict interaction, and accessibility impact.

## Supported-environment status

| Environment | Status | Evidence / boundary |
| --- | --- | --- |
| Ubuntu 24.04 with nftables >= 1.0.9 | validation candidate only | One GitHub-hosted Ubuntu 24.04 run passed the original suite 20 times. The new coexistence and full-uninstall coverage is pending. |
| Ubuntu 22.04 or other Ubuntu releases | unsupported | No retained matrix evidence. |
| Debian (any release) | unsupported | No retained Debian kernel or nftables userspace evidence. |
| nftables < 1.0.9 | unsupported | The runtime rejects it. |
| nftables >= 1.0.9 on an untested distribution | unverified | Version acceptance is not distribution or kernel compatibility evidence. |
| Docker Engine | unsupported for enforcement | Only a synthetic Docker-style nftables preservation test is being added. It is not Docker Engine integration evidence. |
| Pterodactyl/Wings | unsupported for enforcement | Wings uses Docker but needs its own real deployment and traffic validation. |

All candidates also require Linux, `CAP_NET_ADMIN`, an nftables-compatible kernel, and the runtime checks documented in `docs/firewall-integration-testing.md`. The namespace suite additionally requires `CAP_SYS_ADMIN`.

## Remaining activation risks

1. nftables base-chain priority and verdict interactions with an administrator's existing host policy have not yet passed the new restrictive-policy test.
2. Docker and Pterodactyl traffic commonly traverses NAT and forward hooks, while the current backend creates an input hook only. Preservation does not demonstrate protection of published container ports.
3. The original CI evidence covers one GitHub runner image, not supported Ubuntu/Debian release or kernel matrices.
4. The original CI covered firewall cleanup but not the script's systemd, binary, configuration, log, and state removal paths.
5. The system-wide uninstall removes configuration, logs, and persisted state; its operator confirmation, backup/retention policy, and recovery contract need explicit product approval.
6. The backend replaces its own whole table on reconciliation. That is safe only while Shield is the sole owner; extensions must never write into that table independently.

## Gate decision

Do not enable enforcement. The next acceptable action is to run the expanded suite on Ubuntu 24.04, inspect its artifact, and resolve every kernel-observed failure. Then add real Docker, Pterodactyl, Ubuntu, and Debian matrix evidence before revisiting activation.
