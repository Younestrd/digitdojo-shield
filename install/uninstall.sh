#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_PATH="/usr/local/bin/shield"
DAEMON_PATH="/usr/local/bin/shieldd"
SERVICE_NAME="digitdojo-shield.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
CONFIG_DIR="/etc/digitdojo-shield"
LOG_DIR="/var/log/digitdojo-shield"
STATE_DIR="/var/lib/digitdojo-shield"

if [ "${EUID}" -ne 0 ]; then
  echo "DigitDojo Shield uninstall must run as root" >&2
  exit 1
fi

if [ -f "$SERVICE_PATH" ]; then
  systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
  systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
  rm -f "$SERVICE_PATH"
fi

bash "$SCRIPT_DIR/firewall-cleanup.sh"

if [ -f "$BIN_PATH" ]; then
  rm -f "$BIN_PATH"
fi
if [ -f "$DAEMON_PATH" ]; then
  rm -f "$DAEMON_PATH"
fi

systemctl daemon-reload >/dev/null 2>&1 || true

if [ -d "$CONFIG_DIR" ]; then
  rm -rf "$CONFIG_DIR"
fi
if [ -d "$LOG_DIR" ]; then
  rm -rf "$LOG_DIR"
fi
if [ -d "$STATE_DIR" ]; then
  rm -rf "$STATE_DIR"
fi

echo "DigitDojo Shield uninstalled."
