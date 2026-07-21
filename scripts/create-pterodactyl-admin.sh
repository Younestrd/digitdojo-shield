#!/usr/bin/env bash
set -euo pipefail

panel_dir="${1:-/var/www/pterodactyl}"
for file in artisan vendor/autoload.php .env; do [[ -f "$panel_dir/$file" ]] || { echo "Missing $panel_dir/$file" >&2; exit 1; }; done
grep -q '^APP_KEY=.' "$panel_dir/.env" || { echo 'APP_KEY is not configured' >&2; exit 1; }
for variable in ADMIN_EMAIL ADMIN_USERNAME ADMIN_FIRST_NAME ADMIN_LAST_NAME ADMIN_PASSWORD; do [[ -n "${!variable:-}" ]] || { echo "Missing $variable" >&2; exit 1; }; done

cd "$panel_dir"
php artisan migrate:status --no-interaction >/dev/null
php artisan list --raw | grep -qx 'p:user:make' || { echo 'Installed Panel does not support p:user:make' >&2; exit 1; }
php artisan help p:user:make | grep -q -- '--email' || { echo 'Installed p:user:make command does not support non-interactive email input' >&2; exit 1; }
user_count() { php -r "require 'vendor/autoload.php'; \$app=require 'bootstrap/app.php'; \$app->make(Illuminate\\Contracts\\Console\\Kernel::class)->bootstrap(); echo Pterodactyl\\Models\\User::where('email', getenv('ADMIN_EMAIL'))->where('root_admin', true)->count();"; }
count="$(user_count)"
if [[ "$count" == 0 ]]; then
  php artisan p:user:make --email="$ADMIN_EMAIL" --username="$ADMIN_USERNAME" --name-first="$ADMIN_FIRST_NAME" --name-last="$ADMIN_LAST_NAME" --password="$ADMIN_PASSWORD" --admin=1 --no-interaction
  count="$(user_count)"
fi
[[ "$count" == 1 ]] || { echo "Expected exactly one administrator with requested email; found $count" >&2; exit 1; }
echo "Administrator verified: $ADMIN_EMAIL"
