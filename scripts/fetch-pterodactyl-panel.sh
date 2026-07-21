#!/usr/bin/env bash
set -euo pipefail

version="v1.12.4"
sha256="56ee53815d11ed596288208998e368f0ed0ae9f82c7b77ff69acccfa675b382d"
output="${1:-panel.tar.gz}"

curl --fail --location --silent --show-error \
  "https://github.com/pterodactyl/panel/releases/download/${version}/panel.tar.gz" \
  --output "$output"
printf '%s  %s\n' "$sha256" "$output" | sha256sum --check --status
printf 'Verified Pterodactyl Panel %s: %s\n' "$version" "$output"
