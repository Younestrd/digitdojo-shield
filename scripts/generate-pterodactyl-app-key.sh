#!/usr/bin/env bash
set -euo pipefail

panel_dir="${1:-/var/www/pterodactyl}"
env_file="$panel_dir/.env"
for required_file in vendor/autoload.php artisan .env; do
  [[ -f "$panel_dir/$required_file" ]] || { printf 'Missing required Panel file: %s\n' "$panel_dir/$required_file" >&2; exit 1; }
done

key_count="$(grep -c '^APP_KEY=' "$env_file" || true)"
[[ "$key_count" == 1 ]] || { printf 'Expected exactly one APP_KEY entry, found %s\n' "$key_count" >&2; exit 1; }
current_key="$(sed -n 's/^APP_KEY=//p' "$env_file")"
if [[ -z "$current_key" ]]; then
  if ! (cd "$panel_dir" && php artisan key:generate --force); then
    printf 'Laravel APP_KEY generation failed for: %s\n' "$panel_dir" >&2
    exit 1
  fi
fi

key_count="$(grep -c '^APP_KEY=' "$env_file" || true)"
current_key="$(sed -n 's/^APP_KEY=//p' "$env_file")"
[[ "$key_count" == 1 && -n "$current_key" ]] || { printf 'APP_KEY validation failed\n' >&2; exit 1; }
printf 'Laravel APP_KEY is configured: %s\n' "$panel_dir"
