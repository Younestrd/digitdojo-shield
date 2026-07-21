#!/usr/bin/env bash
set -euo pipefail

panel_dir="${1:-/var/www/pterodactyl}"
env_file="$panel_dir/.env"
for required_file in artisan vendor/autoload.php .env; do
  [[ -f "$panel_dir/$required_file" ]] || { printf 'Missing required Panel file: %s\n' "$panel_dir/$required_file" >&2; exit 1; }
done

get_env() { sed -n "s/^$1=//p" "$env_file" | tail -n 1; }
for key in APP_KEY DB_HOST DB_PORT DB_DATABASE DB_USERNAME DB_PASSWORD; do
  value="$(get_env "$key")"
  [[ -n "$value" ]] || { printf 'Missing or empty %s in %s\n' "$key" "$env_file" >&2; exit 1; }
done
command -v mysqladmin >/dev/null 2>&1 || { printf 'mysqladmin is not installed\n' >&2; exit 1; }
command -v mysql >/dev/null 2>&1 || { printf 'mysql client is not installed\n' >&2; exit 1; }

db_host="$(get_env DB_HOST)"; db_port="$(get_env DB_PORT)"; db_name="$(get_env DB_DATABASE)"; db_user="$(get_env DB_USERNAME)"; db_password="$(get_env DB_PASSWORD)"
for attempt in $(seq 1 30); do
  if MYSQL_PWD="$db_password" mysqladmin ping --silent --host="$db_host" --port="$db_port" --user="$db_user"; then break; fi
  [[ "$attempt" == 30 ]] && { printf 'MariaDB did not become available after 30 attempts\n' >&2; exit 1; }
  sleep 1
done

printf 'Running Panel database migrations\n'
(cd "$panel_dir" && php artisan migrate --force)
applied="$(MYSQL_PWD="$db_password" mysql --skip-column-names --host="$db_host" --port="$db_port" --user="$db_user" "$db_name" -e "SELECT COUNT(*) FROM migrations;")"
[[ "$applied" =~ ^[1-9][0-9]*$ ]] || { printf 'Migration validation failed; migrations table is empty or unavailable\n' >&2; exit 1; }
printf 'Panel migrations complete; applied migrations: %s\n' "$applied"
