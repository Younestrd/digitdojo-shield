#!/usr/bin/env bash
set -euo pipefail

required=(PANEL_URL PANEL_APPLICATION_API_KEY PTERODACTYL_LOCATION_ID NODE_NAME NODE_FQDN NODE_SCHEME NODE_MEMORY_MB NODE_DISK_MB NODE_DAEMON_PORT NODE_DAEMON_SFTP_PORT)
for variable in "${required[@]}"; do [[ -n "${!variable:-}" ]] || { printf 'Missing %s\n' "$variable" >&2; exit 1; }; done
command -v curl >/dev/null || { echo 'curl is required' >&2; exit 1; }
command -v jq >/dev/null || { echo 'jq is required' >&2; exit 1; }
[[ "$NODE_SCHEME" == http || "$NODE_SCHEME" == https ]] || { echo 'NODE_SCHEME must be http or https' >&2; exit 1; }
base_url="${PANEL_URL%/}/api/application"
api() { curl --fail --silent --show-error -H 'Accept: Application/vnd.pterodactyl.v1+json' -H "Authorization: Bearer $PANEL_APPLICATION_API_KEY" "$@"; }
nodes="$(api "$base_url/nodes?per_page=100")" || { echo 'Panel Application API is unreachable or rejected the token' >&2; exit 1; }
count="$(jq --arg name "$NODE_NAME" '[.data[].attributes | select(.name == $name)] | length' <<<"$nodes")"
if [[ "$count" == 0 ]]; then
  payload="$(jq -n --arg name "$NODE_NAME" --arg fqdn "$NODE_FQDN" --arg scheme "$NODE_SCHEME" --argjson location_id "$PTERODACTYL_LOCATION_ID" --argjson memory "$NODE_MEMORY_MB" --argjson disk "$NODE_DISK_MB" --argjson daemon_listen "$NODE_DAEMON_PORT" --argjson daemon_sftp "$NODE_DAEMON_SFTP_PORT" '{name:$name,location_id:$location_id,public:true,fqdn:$fqdn,scheme:$scheme,memory:$memory,memory_overallocate:0,disk:$disk,disk_overallocate:0,upload_size:100,daemon_listen:$daemon_listen,daemon_sftp:$daemon_sftp}')"
  api -X POST -H 'Content-Type: application/json' --data "$payload" "$base_url/nodes" >/dev/null
  nodes="$(api "$base_url/nodes?per_page=100")"
  count="$(jq --arg name "$NODE_NAME" '[.data[].attributes | select(.name == $name)] | length' <<<"$nodes")"
fi
[[ "$count" == 1 ]] || { printf 'Expected exactly one node named %s; found %s\n' "$NODE_NAME" "$count" >&2; exit 1; }
node_id="$(jq -r --arg name "$NODE_NAME" '.data[].attributes | select(.name == $name) | .id' <<<"$nodes")"
printf 'PTERODACTYL_NODE_ID=%s\n' "$node_id"
