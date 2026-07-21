#!/usr/bin/env bash
set -u -o pipefail

if [ "${EUID}" -ne 0 ]; then
  echo "docker network diagnostics must run as root" >&2
  exit 1
fi

for command_name in docker ip nft curl; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "required command is unavailable: $command_name" >&2
    exit 1
  fi
done

suffix="${RANDOM}${RANDOM}"
network="shield-diag-net-${suffix}"
web="shield-diag-web-${suffix}"
client_namespace="shield-diag-client-${suffix}"
link_suffix="${RANDOM}"
host_link="sdh${link_suffix}"
client_link="sdc${link_suffix}"
failed=0

cleanup() {
  docker rm --force "$web" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  ip netns delete "$client_namespace" >/dev/null 2>&1 || true
  ip link delete "$host_link" >/dev/null 2>&1 || true
}
trap cleanup EXIT

section() {
  printf '\n===== %s =====\n' "$1"
}

capture_host_state() {
  section "$1: docker info"
  docker info || true
  section "$1: ip address"
  ip addr || true
  section "$1: ip route"
  ip route || true
  ip -6 route || true
  section "$1: nftables ruleset"
  nft list ruleset || true
  section "$1: iptables-save"
  if command -v iptables-save >/dev/null 2>&1; then iptables-save || true; else echo "iptables-save unavailable"; fi
  section "$1: listening TCP sockets"
  ss -ltnp || true
}

probe() {
  local name="$1"
  shift
  section "probe: ${name}"
  if "$@"; then
    echo "RESULT ${name}=success"
  else
    echo "RESULT ${name}=failure"
    failed=1
  fi
}

capture_host_state "before Docker test resources"

docker network create --driver bridge "$network"
docker run --detach --name "$web" --network "$network" --network-alias web --publish 0.0.0.0::80 nginx:1.27-alpine >/dev/null
port="$(docker port "$web" 80/tcp | sed -n '1s/.*://p')"
if [ -z "$port" ]; then
  echo "Docker did not report a published TCP port" >&2
  exit 1
fi

section "Docker network inspect"
docker network inspect "$network" || true
section "Docker port"
docker port "$web" || true
section "Docker inspect"
docker inspect "$web" || true
capture_host_state "after Docker starts"

for attempt in $(seq 1 30); do
  if curl --fail --silent --show-error --connect-timeout 1 "http://127.0.0.1:${port}/" >/dev/null; then break; fi
  sleep 1
done
probe "localhost published port" curl --fail --silent --show-error --connect-timeout 3 "http://127.0.0.1:${port}/"
probe "bridge namespace" docker run --rm --network "$network" curlimages/curl:8.10.1 --fail --silent --show-error --connect-timeout 3 http://web:80/

ip netns add "$client_namespace"
ip link add "$host_link" type veth peer name "$client_link"
ip link set "$client_link" netns "$client_namespace"
ip addr add 198.18.0.1/24 dev "$host_link"
ip link set "$host_link" up
ip -n "$client_namespace" link set lo up
ip -n "$client_namespace" addr add 198.18.0.2/24 dev "$client_link"
ip -n "$client_namespace" link set "$client_link" up
section "external namespace address and route"
ip -n "$client_namespace" addr || true
ip -n "$client_namespace" route || true
probe "external namespace published port" ip netns exec "$client_namespace" curl --fail --silent --show-error --connect-timeout 3 "http://198.18.0.1:${port}/"

capture_host_state "after connectivity probes"
if [ "$failed" -ne 0 ]; then
  section "Docker container logs after failed probe"
  docker logs "$web" || true
  exit 1
fi
