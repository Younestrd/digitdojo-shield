#!/usr/bin/env bash
set -euo pipefail

panel_dir="${1:-/var/www/pterodactyl}"
env_file="$panel_dir/.env"
example_file="$panel_dir/.env.example"
required=(APP_URL APP_ENV APP_DEBUG APP_KEY DB_HOST DB_PORT DB_DATABASE DB_USERNAME DB_PASSWORD REDIS_HOST REDIS_PORT CACHE_DRIVER SESSION_DRIVER QUEUE_CONNECTION)

[[ -f "$example_file" ]] || { printf 'Missing Panel .env.example: %s\n' "$example_file" >&2; exit 1; }
if [[ -e "$env_file" ]] && [[ "${PTERODACTYL_OVERWRITE_ENV:-0}" != 1 ]]; then
  printf 'Refusing to overwrite existing .env: %s\n' "$env_file" >&2
  exit 1
fi

[[ -e "$env_file" ]] || cp "$example_file" "$env_file"
set_value() { sed -i "s|^$1=.*|$1=$2|" "$env_file"; }
set_value APP_URL "${APP_URL:-http://127.0.0.1}"
set_value APP_ENV "${APP_ENV:-production}"
set_value APP_DEBUG "${APP_DEBUG:-false}"
set_value APP_KEY "${APP_KEY:-}"
set_value DB_HOST "${DB_HOST:-127.0.0.1}"
set_value DB_PORT "${DB_PORT:-3306}"
set_value DB_DATABASE "${DB_DATABASE:-panel}"
set_value DB_USERNAME "${DB_USERNAME:-panel}"
set_value DB_PASSWORD "${DB_PASSWORD:-}"
set_value REDIS_HOST "${REDIS_HOST:-127.0.0.1}"
set_value REDIS_PORT "${REDIS_PORT:-6379}"
set_value CACHE_DRIVER "${CACHE_DRIVER:-redis}"
set_value SESSION_DRIVER "${SESSION_DRIVER:-redis}"
set_value QUEUE_CONNECTION "${QUEUE_CONNECTION:-redis}"
for key in "${required[@]}"; do
  count="$(grep -c "^${key}=" "$env_file" || true)"
  [[ "$count" == 1 ]] || { printf 'Expected exactly one %s entry, found %s\n' "$key" "$count" >&2; exit 1; }
done
printf 'Panel environment configured: %s\n' "$env_file"
