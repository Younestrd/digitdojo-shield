#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_DIR="/usr/local/bin"
SERVICE_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/digitdojo-shield"
LOG_DIR="/var/log/digitdojo-shield"
STATE_DIR="/var/lib/digitdojo-shield"
BACKUP_DIR="/var/backups/digitdojo-shield"
SERVICE_NAME="digitdojo-shield.service"
CONFIG_PATH="$CONFIG_DIR/config.yml"
SERVICE_PATH="$SERVICE_DIR/$SERVICE_NAME"

if [ "${EUID}" -ne 0 ]; then
  echo "DigitDojo Shield installation must run as root" >&2
  exit 1
fi
if [ ! -f /etc/os-release ]; then
  echo "Unsupported system: /etc/os-release not found" >&2
  exit 1
fi
for command_name in go install systemctl nft ip; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Required command not found: $command_name" >&2
    exit 1
  fi
done

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf -- "$BUILD_DIR"' EXIT
cd "$ROOT_DIR"
go build -trimpath -o "$BUILD_DIR/shield" ./cmd/shield
go build -trimpath -o "$BUILD_DIR/shieldd" ./cmd/shieldd

install -d -m 0755 "$BINARY_DIR" "$SERVICE_DIR"
install -d -m 0700 "$CONFIG_DIR" "$STATE_DIR" "$BACKUP_DIR"
install -d -m 0750 "$LOG_DIR"

if [ -f "$CONFIG_PATH" ]; then
  cp --preserve=mode,timestamps "$CONFIG_PATH" "$BACKUP_DIR/config.yml.bak"
else
  cat > "$CONFIG_PATH" <<'EOF'
general:
  log_dir: /var/log/digitdojo-shield
  state_dir: /var/lib/digitdojo-shield
  host_based: true
firewall:
  backend: auto
  rate_limit_per_second: 200
  connection_limit: 200
  temporary_ban_seconds: 600
detection:
  packet_threshold: 2000
  connection_threshold: 200
  bytes_threshold: 1048576
  suspicious_spike: 5
  port_scan_threshold: 10
  window_seconds: 30
api:
  enabled: false
  token:
  bind_address: 127.0.0.1:9090
  rate_limit: 30
  rate_burst: 60
alerts:
logging:
  level: info
  rotate: true
EOF
fi
chmod 0600 "$CONFIG_PATH"

install -m 0755 "$BUILD_DIR/shield" "$BINARY_DIR/shield"
install -m 0755 "$BUILD_DIR/shieldd" "$BINARY_DIR/shieldd"
install -m 0644 "$ROOT_DIR/systemd/$SERVICE_NAME" "$SERVICE_PATH"

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo "DigitDojo Shield installed and started."