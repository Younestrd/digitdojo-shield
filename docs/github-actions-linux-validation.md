# GitHub Actions Linux firewall validation

This repository contains the privileged nftables validation workflow at
`.github/workflows/linux-firewall-integration.yml`. It is the only accepted
evidence for opening the firewall enforcement gate.

## Publish the repository

Create or select the intended empty GitHub repository, then set its HTTPS or
SSH URL as `REPOSITORY_URL` in a local shell:

```sh
git remote add origin "$REPOSITORY_URL"
git push -u origin main
```

Confirm the remote before pushing:

```sh
git remote -v
git status --short
```

The repository must retain the `main` branch because the workflow runs on
pushes to that branch. Pull requests also run the suite. A maintainer may start
it manually from the GitHub Actions page through `workflow_dispatch`.

## Runner contract

The workflow uses a GitHub-hosted `ubuntu-24.04` VM and requires only
`contents: read` repository permission. It does not need a deployment token,
write permission, or access to production hosts. Artifact upload uses the
workflow run's artifact storage and does not modify repository contents.

The workflow installs `nftables`, `iproute2`, and `libcap2-bin`, then proves
the runner can:

1. run `nft`;
2. create and delete a network namespace;
3. execute `nft list ruleset` inside that namespace;
4. expose `CAP_NET_ADMIN` to the privileged test process.

The Go suite performs an additional preflight for Linux, nftables 1.0.9 or
newer, `CAP_NET_ADMIN`, and `CAP_SYS_ADMIN`. It exits with an actionable
message before touching a ruleset if any prerequisite is absent.

## Execute and collect evidence

After pushing `main`, select **Linux firewall integration** in Actions and
choose **Run workflow**, or wait for the push-triggered run. The workflow runs
the namespace suite twenty times:

```sh
sudo env "PATH=$PATH" go test -tags=integration -count=20 -v ./internal/firewall
```

Download the `firewall-integration-<run-id>` artifact regardless of result.
For every failed run, retain its log, reproduce the reported namespace test,
add a regression test, and rerun until clean. This workflow itself supplies the
required `-count=20` stability evidence when it is green.

## Gate rule

Passing a workflow does not enable firewall enforcement. The controller must
remain disabled until the kernel evidence, rollback evidence, cleanup evidence,
and repeated stability evidence are reviewed together.
