#!/usr/bin/env bash
set -euo pipefail

for variable in PANEL_URL PANEL_APPLICATION_API_KEY PTERODACTYL_NODE_ID ALLOCATION_IP ALLOCATION_PORTS; do [[ -n "${!variable:-}" ]] || { echo "Missing $variable" >&2; exit 1; }; done
command -v curl >/dev/null && command -v jq >/dev/null && command -v python3 >/dev/null || { echo 'curl, jq, and python3 are required' >&2; exit 1; }
python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$ALLOCATION_IP" || { echo 'ALLOCATION_IP is invalid' >&2; exit 1; }
declare -A ports
IFS=',' read -ra tokens <<<"$ALLOCATION_PORTS"
for token in "${tokens[@]}"; do
  if [[ "$token" =~ ^([0-9]+)-([0-9]+)$ ]]; then start="${BASH_REMATCH[1]}"; end="${BASH_REMATCH[2]}"; else start="$token"; end="$token"; fi
  [[ "$start" =~ ^[0-9]+$ && "$end" =~ ^[0-9]+$ && "$start" -ge 1 && "$end" -le 65535 && "$start" -le "$end" ]] || { echo "Invalid port token: $token" >&2; exit 1; }
  for port in $(seq "$start" "$end"); do [[ -z "${ports[$port]:-}" ]] || { echo "Duplicate port: $port" >&2; exit 1; }; ports[$port]=1; done
done
base_url="${PANEL_URL%/}/api/application"; api() { curl --fail --silent --show-error -H 'Accept: Application/vnd.pterodactyl.v1+json' -H "Authorization: Bearer $PANEL_APPLICATION_API_KEY" "$@"; }
existing="$(api "$base_url/nodes/$PTERODACTYL_NODE_ID/allocations?per_page=100")" || { echo 'Panel Application API is unreachable or rejected the token' >&2; exit 1; }
created=0; already=0
for port in "${!ports[@]}"; do
  if jq -e --arg ip "$ALLOCATION_IP" --argjson port "$port" '.data[].attributes | select(.ip == $ip and .port == $port)' <<<"$existing" >/dev/null; then ((already+=1)); else api -X POST -H 'Content-Type: application/json' --data "$(jq -n --arg ip "$ALLOCATION_IP" --arg port "$port" '{ip:$ip,ports:[$port]}')" "$base_url/nodes/$PTERODACTYL_NODE_ID/allocations" >/dev/null; ((created+=1)); fi
done
final="$(api "$base_url/nodes/$PTERODACTYL_NODE_ID/allocations?per_page=100")"
for port in "${!ports[@]}"; do jq -e --arg ip "$ALLOCATION_IP" --argjson port "$port" '.data[].attributes | select(.ip == $ip and .port == $port)' <<<"$final" >/dev/null || { echo "Allocation missing after creation: $ALLOCATION_IP:$port" >&2; exit 1; }; done
printf 'TOTAL_REQUESTED=%s\nALREADY_EXISTED=%s\nNEWLY_CREATED=%s\nFINAL_ALLOCATION_COUNT=%s\n' "${#ports[@]}" "$already" "$created" "$(jq '.data | length' <<<"$final")"
