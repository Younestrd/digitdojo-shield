#!/usr/bin/env bash
set -euo pipefail

if [ "${EUID}" -ne 0 ]; then
  echo "DigitDojo Shield firewall cleanup must run as root" >&2
  exit 1
fi
if ! command -v nft >/dev/null 2>&1; then
  echo "Cannot verify Shield firewall cleanup: nft is not installed" >&2
  exit 1
fi

SHIELD_CLEANUP_PROGRAM='destroy table inet digitdojo_shield'
printf '%s\n' "$SHIELD_CLEANUP_PROGRAM" | nft --check --file -
printf '%s\n' "$SHIELD_CLEANUP_PROGRAM" | nft --file -
