#!/usr/bin/env bash
set -euo pipefail

panel_dir="${1:-/var/www/pterodactyl}"
for file in artisan vendor/autoload.php .env; do [[ -f "$panel_dir/$file" ]] || { echo "Missing $panel_dir/$file" >&2; exit 1; }; done
[[ -n "${ADMIN_EMAIL:-}" ]] || { echo 'Missing ADMIN_EMAIL' >&2; exit 1; }
cd "$panel_dir"
php artisan migrate:status --no-interaction >/dev/null || { echo 'Panel migrations are incomplete' >&2; exit 1; }
admin_count="$(php -r "require 'vendor/autoload.php'; \$app=require 'bootstrap/app.php'; \$app->make(Illuminate\\Contracts\\Console\\Kernel::class)->bootstrap(); echo Pterodactyl\\Models\\User::where('email', getenv('ADMIN_EMAIL'))->where('root_admin', true)->count();")"
[[ "$admin_count" == 1 ]] || { echo 'Requested administrator does not exist exactly once' >&2; exit 1; }
version="$(php artisan --version)"
commands="$(php artisan list --raw)"
printf 'Installed Panel: %s\n' "$version"
if grep -Eq '^(p:api:key|p:application-api:key|api:key)$' <<<"$commands"; then
  echo 'An API-key Artisan command was detected, but its interface is not a documented stable bootstrap contract; refusing to invoke it automatically.' >&2
  exit 1
fi
echo 'No officially supported non-interactive Application API-key bootstrap command is exposed by this installed Panel version.' >&2
echo 'Create the key through the Panel-supported administrator interface, or use an upstream-supported bootstrap mechanism before running Application API scripts.' >&2
exit 1
