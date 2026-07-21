#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
destination="${1:-/var/www/pterodactyl}"

if [[ -e "$destination" ]] && [[ -n "$(find "$destination" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]]; then
  printf 'Refusing to extract Panel into non-empty directory: %s\n' "$destination" >&2
  exit 1
fi

archive_dir="$(mktemp -d)"
trap 'rm -rf "$archive_dir"' EXIT
archive="$archive_dir/panel.tar.gz"

"$script_dir/fetch-pterodactyl-panel.sh" "$archive"
install -d -m 0755 "$destination"
tar -xzf "$archive" -C "$destination"

required_files=(artisan composer.json .env.example public/index.php bootstrap/app.php)
for required_file in "${required_files[@]}"; do
  if [[ ! -f "$destination/$required_file" ]]; then
    printf 'Panel archive is missing required file: %s\n' "$required_file" >&2
    exit 1
  fi
done

printf 'Pterodactyl Panel files prepared in %s\n' "$destination"
