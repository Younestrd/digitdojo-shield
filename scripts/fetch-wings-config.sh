#!/usr/bin/env bash
set -euo pipefail

for variable in PANEL_URL PANEL_APPLICATION_API_KEY PTERODACTYL_NODE_ID; do [[ -n "${!variable:-}" ]] || { echo "Missing $variable" >&2; exit 1; }; done
output="${WINGS_CONFIG_OUTPUT:-config.yml}"
[[ ! -e "$output" || "${WINGS_OVERWRITE_CONFIG:-0}" == 1 ]] || { echo "Refusing to overwrite existing configuration: $output" >&2; exit 1; }
command -v curl >/dev/null && command -v jq >/dev/null || { echo 'curl and jq are required' >&2; exit 1; }
base_url="${PANEL_URL%/}/api/application"
api() { curl --fail --silent --show-error -H 'Accept: Application/vnd.pterodactyl.v1+json' -H "Authorization: Bearer $PANEL_APPLICATION_API_KEY" "$@"; }
node="$(api "$base_url/nodes/$PTERODACTYL_NODE_ID")" || { echo 'Panel Application API is unreachable or rejected the token' >&2; exit 1; }
node_uuid="$(jq -r '.attributes.uuid // .data.attributes.uuid // empty' <<<"$node")"
[[ -n "$node_uuid" ]] || { echo "Node $PTERODACTYL_NODE_ID was not returned by the Application API" >&2; exit 1; }
response="$(api "$base_url/nodes/$PTERODACTYL_NODE_ID/configuration")"
if jq -e . >/dev/null 2>&1 <<<"$response"; then response="$(jq -r '.configuration // .attributes.configuration // .data.attributes.configuration // empty' <<<"$response")"; fi
[[ -n "$response" ]] || { echo 'Panel returned an empty Wings configuration' >&2; exit 1; }
printf '%s\n' "$response" > "$output"
[[ -s "$output" ]] || { echo "Wings configuration was not written: $output" >&2; exit 1; }
for key in uuid token_id token api system docker remote; do grep -q "^${key}:" "$output" || { echo "Downloaded Wings configuration is missing key: $key" >&2; exit 1; }; done
grep -q "^uuid: ${node_uuid}$" "$output" || { echo "Downloaded Wings configuration UUID does not match node $PTERODACTYL_NODE_ID" >&2; exit 1; }
printf 'Official Wings configuration saved: %s\n' "$output"
