#!/usr/bin/env bash
set -euo pipefail

for variable in PANEL_URL PANEL_APPLICATION_API_KEY LOCATION_SHORT LOCATION_DESCRIPTION; do
  [[ -n "${!variable:-}" ]] || { printf 'Missing %s\n' "$variable" >&2; exit 1; }
done
command -v curl >/dev/null || { echo 'curl is required' >&2; exit 1; }
command -v jq >/dev/null || { echo 'jq is required' >&2; exit 1; }
base_url="${PANEL_URL%/}/api/application"
api() { curl --fail --silent --show-error -H 'Accept: Application/vnd.pterodactyl.v1+json' -H "Authorization: Bearer $PANEL_APPLICATION_API_KEY" "$@"; }

locations="$(api "$base_url/locations?per_page=100")" || { echo 'Panel Application API is unreachable or rejected the token' >&2; exit 1; }
count="$(jq --arg short "$LOCATION_SHORT" '[.data[].attributes | select(.short == $short)] | length' <<<"$locations")"
if [[ "$count" == 0 ]]; then
  api -X POST -H 'Content-Type: application/json' --data "$(jq -n --arg short "$LOCATION_SHORT" --arg long "$LOCATION_DESCRIPTION" '{short:$short,long:$long}')" "$base_url/locations" >/dev/null
  locations="$(api "$base_url/locations?per_page=100")"
  count="$(jq --arg short "$LOCATION_SHORT" '[.data[].attributes | select(.short == $short)] | length' <<<"$locations")"
fi
[[ "$count" == 1 ]] || { printf 'Expected exactly one location with short code %s; found %s\n' "$LOCATION_SHORT" "$count" >&2; exit 1; }
location_id="$(jq -r --arg short "$LOCATION_SHORT" '.data[].attributes | select(.short == $short) | .id' <<<"$locations")"
printf 'PTERODACTYL_LOCATION_ID=%s\n' "$location_id"
