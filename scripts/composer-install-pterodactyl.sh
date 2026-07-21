#!/usr/bin/env bash
set -euo pipefail

panel_dir="${1:-/var/www/pterodactyl}"
for required_file in composer.json .env artisan composer.lock; do
  [[ -f "$panel_dir/$required_file" ]] || { printf 'Missing required Panel file: %s\n' "$panel_dir/$required_file" >&2; exit 1; }
done
command -v composer >/dev/null 2>&1 || { printf 'Composer is not installed or not on PATH\n' >&2; exit 1; }

if ! composer --working-dir="$panel_dir" install --no-interaction --prefer-dist --optimize-autoloader; then
  printf 'Composer installation failed for Panel directory: %s\n' "$panel_dir" >&2
  exit 1
fi

for required_file in vendor/autoload.php artisan composer.lock vendor/laravel/framework/composer.json; do
  [[ -f "$panel_dir/$required_file" ]] || { printf 'Composer validation failed; missing: %s\n' "$panel_dir/$required_file" >&2; exit 1; }
done
printf 'Composer dependencies installed and validated: %s\n' "$panel_dir"
