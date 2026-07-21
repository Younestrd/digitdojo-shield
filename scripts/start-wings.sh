#!/usr/bin/env bash
set -euo pipefail

wings_binary="${WINGS_BINARY:-wings}"
wings_config="${WINGS_CONFIG:-config.yml}"
log_file="${WINGS_LOG_FILE:-wings.log}"
command -v "$wings_binary" >/dev/null 2>&1 || [[ -x "$wings_binary" ]] || { echo "Wings binary is not executable: $wings_binary" >&2; exit 1; }
[[ -r "$wings_config" ]] || { echo "Wings configuration is not readable: $wings_config" >&2; exit 1; }
command -v ss >/dev/null || { echo 'ss is required to verify Wings ports' >&2; exit 1; }

api_port="$(awk '/^api:/{inside=1;next} inside && /^[^[:space:]]/{exit} inside && /^[[:space:]]*port:/{gsub(/[^0-9]/,"",$0);print;exit}' "$wings_config")"
sftp_port="$(awk '/^[[:space:]]*sftp:/{inside=1;next} inside && /^[[:space:]]*bind_port:/{gsub(/[^0-9]/,"",$0);print;exit}' "$wings_config")"
[[ "$api_port" =~ ^[0-9]+$ && "$sftp_port" =~ ^[0-9]+$ ]] || { echo 'Unable to read Wings API/SFTP ports from configuration' >&2; exit 1; }

if command -v systemctl >/dev/null 2>&1 && systemctl cat wings.service >/dev/null 2>&1; then
  systemctl start wings.service
  process_check() { systemctl is-active --quiet wings.service; }
  log_check() { journalctl -u wings.service -n 100 --no-pager; }
else
  nohup "$wings_binary" --config "$wings_config" >"$log_file" 2>&1 &
  wings_pid=$!
  process_check() { kill -0 "$wings_pid" 2>/dev/null; }
  log_check() { cat "$log_file"; }
fi
for attempt in $(seq 1 20); do
  if process_check && ss -ltn | grep -q ":${api_port} " && ss -ltn | grep -q ":${sftp_port} "; then
    if ! log_check | grep -qiE 'fatal|panic'; then echo "Wings operational: API $api_port, SFTP $sftp_port"; exit 0; fi
  fi
  sleep 1
done
log_check >&2 || true
echo 'Wings did not become operational' >&2
exit 1
