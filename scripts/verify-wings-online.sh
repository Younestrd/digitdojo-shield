#!/usr/bin/env bash
set -euo pipefail

for variable in PANEL_URL PANEL_APPLICATION_API_KEY PTERODACTYL_NODE_ID; do [[ -n "${!variable:-}" ]] || { echo "Missing $variable" >&2; exit 1; }; done
wings_config="${WINGS_CONFIG:-config.yml}"
[[ -r "$wings_config" ]] || { echo "Wings configuration is not readable: $wings_config" >&2; exit 1; }
command -v curl >/dev/null && command -v jq >/dev/null && command -v ss >/dev/null && command -v pgrep >/dev/null || { echo 'curl, jq, ss, and pgrep are required' >&2; exit 1; }
api_port="$(awk '/^api:/{inside=1;next} inside && /^[^[:space:]]/{exit} inside && /^[[:space:]]*port:/{gsub(/[^0-9]/,"",$0);print;exit}' "$wings_config")"
config_uuid="$(sed -n 's/^uuid: //p' "$wings_config" | head -n1)"
[[ "$api_port" =~ ^[0-9]+$ && -n "$config_uuid" ]] || { echo 'Unable to read Wings API port or UUID' >&2; exit 1; }
base_url="${PANEL_URL%/}/api/application"; api() { curl --fail --silent --show-error -H 'Accept: Application/vnd.pterodactyl.v1+json' -H "Authorization: Bearer $PANEL_APPLICATION_API_KEY" "$@"; }
for attempt in $(seq 1 60); do
  node="$(api "$base_url/nodes/$PTERODACTYL_NODE_ID" 2>/dev/null || true)"
  if [[ -n "$node" ]] && pgrep -f '[w]ings' >/dev/null && ss -ltn | grep -q ":${api_port} "; then
    node_uuid="$(jq -r '.attributes.uuid // .data.attributes.uuid // empty' <<<"$node")"
    maintenance="$(jq -r '.attributes.maintenance_mode // .data.attributes.maintenance_mode // true' <<<"$node")"
    if [[ "$node_uuid" == "$config_uuid" && "$maintenance" != true ]]; then
      printf '✓ Panel reachable\n✓ Wings running\n✓ Wings API reachable\n✓ Node registered\n✓ Node online\n✓ Panel ↔ Wings communication verified\n'
      exit 0
    fi
  fi
  sleep 1
done
echo 'Wings did not become online through the Panel Application API within 60 seconds' >&2
exit 1
